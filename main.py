# -*- coding: utf-8 -*-
"""
Домашнее задание: Анализ логов для поиска негативных событий
Студент: Калентьев Никита
Группа: МКБ251
Дата: 21.02.2026
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import os

print("=" * 60)
print("НАЧАЛО АНАЛИЗА ЛОГОВ")
print("=" * 60)

# Настройка стилей для графиков
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")

# Этап 1: Загрузка и подготовка данных
print("\n[ЭТАП 1] Загрузка и подготовка данных")
print("-" * 40)

# Загрузка данных из JSON файла
print("1. Загружаем данные из файла botsv1.json...")
try:
    with open('botsv1.json', 'r', encoding='utf-8') as file:
        data = json.load(file)
    print(f"   Успешно! Загружено {len(data)} записей")
except FileNotFoundError:
    print("   ОШИБКА: Файл botsv1.json не найден!")
    print("   Убедитесь, что файл находится в той же папке, что и main.py")
    exit()

# Преобразуем данные в DataFrame
print("2. Преобразуем данные в DataFrame...")
df = pd.json_normalize(data)
print(f"   Размерность данных: {df.shape[0]} строк, {df.shape[1]} столбцов")

# Разделяем логи на WinEventLog и DNS
print("3. Разделяем логи на типы...")
df_winevent = df[df['result.sourcetype'] == 'WinEventLog:Security'].copy()
df_dns = df[df['result.EventCode'] == 'DNS'].copy()

print(f"   WinEventLog: {len(df_winevent)} записей")
print(f"   DNS логи: {len(df_dns)} записей")

# Проверяем, есть ли DNS логи
if len(df_dns) == 0:
    print("\n   ВНИМАНИЕ: DNS логи не найдены в загруженных данных!")
    print("   Будут проанализированы только WinEventLog")
    print("   Для полного анализа требуется больше данных DNS логов")

# Нормализация данных
print("\n4. Выполняем нормализацию данных...")

# Для WinEventLog: извлекаем EventID
if len(df_winevent) > 0:
    df_winevent['EventID'] = df_winevent['result.EventCode'].astype(str)
    df_winevent['Computer'] = df_winevent['result.ComputerName']
    df_winevent['Time'] = pd.to_datetime(df_winevent['result._time'], errors='coerce')
    print(f"   WinEventLog: обработано {len(df_winevent)} записей")

# Для DNS логов: извлекаем QueryName
if len(df_dns) > 0:
    # Проверяем наличие полей DNS
    dns_fields = ['result.QueryName', 'result.QueryType', 'result.ClientIP']
    for field in dns_fields:
        if field not in df_dns.columns:
            df_dns[field] = None
    
    df_dns['QueryName'] = df_dns['result.QueryName']
    df_dns['QueryType'] = df_dns['result.QueryType']
    df_dns['ClientIP'] = df_dns['result.ClientIP']
    df_dns['Computer'] = df_dns['result.ComputerName']
    df_dns['Time'] = pd.to_datetime(df_dns['result._time'], errors='coerce')
    print(f"   DNS логи: обработано {len(df_dns)} записей")

print("\n[ЭТАП 2] Анализ данных")
print("-" * 40)

# Анализ WinEventLog
print("\n1. Анализ WinEventLog:")

# Список подозрительных EventID
suspicious_events = {
    '4624': 'Успешный вход (следить за необычными)',
    '4625': 'Неудачная попытка входа (брутфорс)',
    '4648': 'Вход с явными учетными данными',
    '4672': 'Назначение специальных привилегий',
    '4688': 'Создание процесса (следить за подозрительными)',
    '4698': 'Создание задания',
    '4703': 'Изменение прав пользователя',
    '4720': 'Создание пользователя',
    '4732': 'Добавление в группу',
    '4740': 'Блокировка учетной записи'
}

if len(df_winevent) > 0:
    # Находим подозрительные события
    df_winevent_suspicious = df_winevent[df_winevent['EventID'].isin(suspicious_events.keys())].copy()
    df_winevent_suspicious['Description'] = df_winevent_suspicious['EventID'].map(suspicious_events)
    
    print(f"   Найдено {len(df_winevent_suspicious)} подозрительных событий")
    
    # Статистика по EventID
    event_stats = df_winevent_suspicious['EventID'].value_counts().reset_index()
    event_stats.columns = ['EventID', 'Count']
    event_stats['Description'] = event_stats['EventID'].map(suspicious_events)
    
    print("\n   Статистика подозрительных событий:")
    for _, row in event_stats.head(10).iterrows():
        print(f"   - EventID {row['EventID']}: {row['Count']} раз ({row['Description']})")
else:
    print("   Нет данных для анализа WinEventLog")

# Анализ DNS логов
print("\n2. Анализ DNS логов:")

# Список подозрительных доменов
suspicious_domains = [
    'ajd92jd9d.com',
    'c2.maliciousdomain.com',
    'malware.com',
    'c2server.com',
    'botnet.com',
    'phishing.com',
    'ddns.net',
    'dyndns.org',
    'no-ip.com'
]

if len(df_dns) > 0:
    # Проверяем на наличие подозрительных доменов
    df_dns['IsSuspicious'] = df_dns['QueryName'].astype(str).apply(
        lambda x: any(domain in str(x).lower() for domain in suspicious_domains) if pd.notna(x) else False
    )
    
    df_dns_suspicious = df_dns[df_dns['IsSuspicious'] == True].copy()
    print(f"   Найдено {len(df_dns_suspicious)} подозрительных DNS запросов")
    
    if len(df_dns_suspicious) > 0:
        dns_stats = df_dns_suspicious['QueryName'].value_counts().reset_index()
        dns_stats.columns = ['Domain', 'Count']
        
        print("\n   Подозрительные домены:")
        for _, row in dns_stats.head(10).iterrows():
            print(f"   - {row['Domain']}: {row['Count']} запросов")
    else:
        print("   Подозрительных доменов не найдено")
        
        # Альтернативный анализ: находим редкие домены
        if len(df_dns) > 0:
            domain_counts = df_dns['QueryName'].value_counts()
            rare_domains = domain_counts[domain_counts <= domain_counts.quantile(0.25)]
            print(f"   Найдено {len(rare_domains)} редких доменов")
else:
    print("   Нет данных для анализа DNS логов")

print("\n[ЭТАП 3] Визуализация данных")
print("-" * 40)

# Создаем фигуру для графиков
fig = plt.figure(figsize=(16, 10))

# График 1: Топ подозрительных событий WinEventLog
if len(df_winevent) > 0:
    ax1 = plt.subplot(2, 2, 1)
    
    # Получаем топ-10 подозрительных событий
    if len(df_winevent_suspicious) > 0:
        top_winevent = df_winevent_suspicious['EventID'].value_counts().head(10)
        
        if len(top_winevent) > 0:
            bars1 = ax1.bar(range(len(top_winevent)), top_winevent.values, color='skyblue', edgecolor='navy')
            ax1.set_xticks(range(len(top_winevent)))
            ax1.set_xticklabels([f"ID: {x}" for x in top_winevent.index], rotation=45, ha='right')
            ax1.set_xlabel('Event ID')
            ax1.set_ylabel('Количество событий')
            ax1.set_title('Топ-10 подозрительных событий WinEventLog')
            
            # Добавляем значения на столбцы
            for i, (bar, val) in enumerate(zip(bars1, top_winevent.values)):
                ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, 
                        str(val), ha='center', va='bottom', fontsize=9)
    else:
        ax1.text(0.5, 0.5, 'Нет подозрительных событий', 
                ha='center', va='center', transform=ax1.transAxes)
        ax1.set_title('WinEventLog (нет данных)')
else:
    ax1 = plt.subplot(2, 2, 1)
    ax1.text(0.5, 0.5, 'Нет данных WinEventLog', 
            ha='center', va='center', transform=ax1.transAxes)
    ax1.set_title('WinEventLog (нет данных)')

# График 2: Топ подозрительных DNS запросов
if len(df_dns) > 0:
    ax2 = plt.subplot(2, 2, 2)
    
    if len(df_dns_suspicious) > 0:
        top_dns = df_dns_suspicious['QueryName'].value_counts().head(10)
        
        if len(top_dns) > 0:
            # Обрезаем длинные имена для читаемости
            short_names = [name[:30] + '...' if len(str(name)) > 30 else name for name in top_dns.index]
            
            bars2 = ax2.barh(range(len(top_dns)), top_dns.values, color='lightcoral', edgecolor='darkred')
            ax2.set_yticks(range(len(top_dns)))
            ax2.set_yticklabels(short_names)
            ax2.set_xlabel('Количество запросов')
            ax2.set_title('Топ-10 подозрительных DNS запросов')
            
            # Добавляем значения
            for i, (bar, val) in enumerate(zip(bars2, top_dns.values)):
                ax2.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, 
                        str(val), ha='left', va='center', fontsize=9)
    else:
        # Если нет подозрительных, показываем топ всех запросов
        top_all_dns = df_dns['QueryName'].value_counts().head(10)
        
        if len(top_all_dns) > 0:
            short_names = [name[:30] + '...' if len(str(name)) > 30 else name for name in top_all_dns.index]
            
            bars2 = ax2.barh(range(len(top_all_dns)), top_all_dns.values, color='lightgreen', edgecolor='darkgreen')
            ax2.set_yticks(range(len(top_all_dns)))
            ax2.set_yticklabels(short_names)
            ax2.set_xlabel('Количество запросов')
            ax2.set_title('Топ-10 DNS запросов (подозрительных не найдено)')
            
            for i, (bar, val) in enumerate(zip(bars2, top_all_dns.values)):
                ax2.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, 
                        str(val), ha='left', va='center', fontsize=9)
        else:
            ax2.text(0.5, 0.5, 'Нет DNS запросов', 
                    ha='center', va='center', transform=ax2.transAxes)
            ax2.set_title('DNS логи (нет данных)')
else:
    ax2 = plt.subplot(2, 2, 2)
    ax2.text(0.5, 0.5, 'Нет данных DNS логов', 
            ha='center', va='center', transform=ax2.transAxes)
    ax2.set_title('DNS логи (нет данных)')

# График 3: Сравнение количества событий по типам
ax3 = plt.subplot(2, 2, 3)

log_types = []
log_counts = []

if len(df_winevent) > 0:
    log_types.append('WinEventLog\n(все)')
    log_counts.append(len(df_winevent))
    
    if len(df_winevent_suspicious) > 0:
        log_types.append('WinEventLog\n(подозрительные)')
        log_counts.append(len(df_winevent_suspicious))

if len(df_dns) > 0:
    log_types.append('DNS логи\n(все)')
    log_counts.append(len(df_dns))
    
    if len(df_dns_suspicious) > 0:
        log_types.append('DNS логи\n(подозрительные)')
        log_counts.append(len(df_dns_suspicious))

if log_types:
    colors3 = ['#2ecc71', '#e74c3c', '#3498db', '#f39c12'][:len(log_types)]
    bars3 = ax3.bar(log_types, log_counts, color=colors3, edgecolor='black')
    ax3.set_ylabel('Количество событий')
    ax3.set_title('Сравнение количества событий')
    
    for bar, val in zip(bars3, log_counts):
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, 
                str(val), ha='center', va='bottom', fontsize=10)
else:
    ax3.text(0.5, 0.5, 'Нет данных для сравнения', 
            ha='center', va='center', transform=ax3.transAxes)
    ax3.set_title('Сравнение (нет данных)')

# График 4: Круговая диаграмма подозрительных событий
ax4 = plt.subplot(2, 2, 4)

suspicious_counts = []
suspicious_labels = []

if len(df_winevent_suspicious) > 0:
    suspicious_counts.append(len(df_winevent_suspicious))
    suspicious_labels.append('WinEventLog\nподозрительные')

if len(df_dns_suspicious) > 0:
    suspicious_counts.append(len(df_dns_suspicious))
    suspicious_labels.append('DNS\nподозрительные')

if suspicious_counts:
    colors4 = ['#ff6b6b', '#4ecdc4']
    ax4.pie(suspicious_counts, labels=suspicious_labels, autopct='%1.1f%%',
            colors=colors4[:len(suspicious_counts)], startangle=90, explode=[0.05]*len(suspicious_counts))
    ax4.set_title('Распределение подозрительных событий')
else:
    ax4.text(0.5, 0.5, 'Нет подозрительных событий', 
            ha='center', va='center', transform=ax4.transAxes)
    ax4.set_title('Подозрительные события (нет данных)')

plt.tight_layout()
plt.suptitle('Анализ логов на предмет негативных событий', fontsize=16, y=1.02)
plt.savefig('analysis_results.png', dpi=300, bbox_inches='tight')
print("\n   Графики сохранены в файл 'analysis_results.png'")

# Вывод результатов в консоль
print("\n" + "=" * 60)
print("ИТОГОВЫЕ РЕЗУЛЬТАТЫ АНАЛИЗА")
print("=" * 60)

print(f"\nВсего записей в логах: {len(df)}")
print(f"WinEventLog: {len(df_winevent)} записей")
print(f"DNS логи: {len(df_dns)} записей")

print(f"\nПодозрительных событий WinEventLog: {len(df_winevent_suspicious) if len(df_winevent) > 0 else 0}")
print(f"Подозрительных DNS запросов: {len(df_dns_suspicious) if len(df_dns) > 0 else 0}")

if len(df_winevent_suspicious) > 0:
    print(f"\nТоп-5 подозрительных EventID:")
    top5_events = df_winevent_suspicious['EventID'].value_counts().head(5)
    for event_id, count in top5_events.items():
        print(f"  - EventID {event_id}: {count} раз ({suspicious_events.get(event_id, 'Неизвестное событие')})")

if len(df_dns_suspicious) > 0:
    print(f"\nТоп-5 подозрительных доменов:")
    top5_domains = df_dns_suspicious['QueryName'].value_counts().head(5)
    for domain, count in top5_domains.items():
        print(f"  - {domain}: {count} запросов")

print("\n" + "=" * 60)
print("АНАЛИЗ ЗАВЕРШЕН")
print("=" * 60)
print("\nРезультаты сохранены в файл 'analysis_results.png'")
print("Для просмотра графика откройте этот файл")

# Сохраняем результаты в CSV
if len(df_winevent_suspicious) > 0:
    df_winevent_suspicious[['EventID', 'Description', 'Computer', 'Time']].to_csv('suspicious_winevents.csv', index=False)
    print("Подозрительные события WinEventLog сохранены в 'suspicious_winevents.csv'")

if len(df_dns_suspicious) > 0:
    df_dns_suspicious[['QueryName', 'QueryType', 'ClientIP', 'Computer', 'Time']].to_csv('suspicious_dns.csv', index=False)
    print("Подозрительные DNS запросы сохранены в 'suspicious_dns.csv'")

plt.show()