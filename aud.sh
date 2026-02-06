#!/bin/bash

#################################################################################
#
#   VPS Security Auditor
#   15 модулей безопасности для VPS
#
#################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
NC='\033[0m'

MODULES_LIST="authentication accounting boot_services kernel filesystems firewalls networking logging malware ssh time hardening shells file_permissions"

MYID=$(id -u 2>/dev/null)
if [ ${MYID} -eq 0 ]; then
    PRIVILEGED=1
    RUNNING_USER="root"
else
    PRIVILEGED=0
    RUNNING_USER=$(whoami)
fi

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARNING_TESTS=0
SKIPPED_TESTS=0

run_vps_modules() {
    echo "========================================================================"
    echo "VPS АУДИТ БЕЗОПАСНОСТИ"
    echo "Пользователь: ${RUNNING_USER}"
    echo "Привилегии: $( [ ${PRIVILEGED} -eq 1 ] && echo "ROOT" || echo "обычный" )"
    echo "========================================================================"
    
    START_TIME=$(date +%s)
    MODULE_COUNT=1
    
    for MODULE in ${MODULES_LIST}; do
        echo ""
        printf "МОДУЛЬ %02d/15: ${MODULE}\n" ${MODULE_COUNT}
        echo "────────────────────────────────────────────────────────────"
        
        case "${MODULE}" in
            authentication)
                run_auth_tests
                ;;
            accounting)
                run_accounting_tests
                ;;
            boot_services)
                run_boot_tests
                ;;
            kernel)
                run_kernel_tests
                ;;
            filesystems)
                run_filesystem_tests
                ;;
            firewalls)
                run_firewall_tests
                ;;
            networking)
                run_networking_tests
                ;;
            logging)
                run_logging_tests
                ;;
            malware)
                run_malware_tests
                ;;
            ssh)
                run_ssh_tests
                ;;
            time)
                run_time_tests
                ;;
            hardening)
                run_hardening_tests
                ;;
            shells)
                run_shells_tests
                ;;
            file_permissions)
                run_file_perm_tests
                ;;
        esac
        
        MODULE_COUNT=$((MODULE_COUNT + 1))
    done
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    
    echo ""
    echo "========================================================================"
    echo "ИТОГИ"
    printf "Всего тестов:     %d\n" ${TOTAL_TESTS}
    printf "Успешно:          %d\n" ${PASSED_TESTS}
    printf "С ошибками:       %d\n" ${FAILED_TESTS}
    printf "Предупреждений:   %d\n" ${WARNING_TESTS}
    printf "Пропущено:        %d\n" ${SKIPPED_TESTS}
    printf "Время выполнения: %d секунд\n" ${DURATION}
    
    if [ ${TOTAL_TESTS} -gt 0 ]; then
        SUCCESS_PERCENT=$((PASSED_TESTS * 100 / TOTAL_TESTS))
        printf "Успешных тестов:  %d%%\n" ${SUCCESS_PERCENT}
    fi
}

run_auth_tests() {
    local tests=0
    
    if [ -f "/etc/passwd" ]; then
        local passwd_owner=$(stat -c '%U' /etc/passwd 2>/dev/null || ls -ld /etc/passwd | awk '{print $3}')
        local passwd_perms=$(stat -c '%a' /etc/passwd 2>/dev/null || ls -ld /etc/passwd | cut -c2-4)
        
        if [ "$passwd_owner" = "root" ]; then
            echo "${GREEN}✓${NC} /etc/passwd: владелец root"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo "${RED}✗${NC} /etc/passwd: владелец $passwd_owner"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
        tests=$((tests + 1))
        
        if [ "$passwd_perms" = "644" ]; then
            echo "${GREEN}✓${NC} /etc/passwd: права 644"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo "${YELLOW}⚠${NC} /etc/passwd: права $passwd_perms"
            WARNING_TESTS=$((WARNING_TESTS + 1))
        fi
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/shadow" ]; then
        local shadow_perms=$(stat -c '%a' /etc/shadow 2>/dev/null || ls -ld /etc/shadow | cut -c2-4)
        if [ "$shadow_perms" -le 640 ]; then
            echo "${GREEN}✓${NC} /etc/shadow: права $shadow_perms"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo "${RED}✗${NC} /etc/shadow: права $shadow_perms"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/login.defs" ]; then
        if grep -q "^PASS_MAX_DAYS" /etc/login.defs; then
            local max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
            if [ "$max_days" -le 90 ]; then
                echo "${GREEN}✓${NC} Макс. срок пароля: $max_days дней"
                PASSED_TESTS=$((PASSED_TESTS + 1))
            else
                echo "${YELLOW}⚠${NC} Макс. срок пароля: $max_days дней"
                WARNING_TESTS=$((WARNING_TESTS + 1))
            fi
        else
            echo "${YELLOW}⚠${NC} PASS_MAX_DAYS не настроен"
            WARNING_TESTS=$((WARNING_TESTS + 1))
        fi
        tests=$((tests + 1))
    fi
    
    if [ -d "/etc/pam.d" ]; then
        local pam_files=$(ls /etc/pam.d/ 2>/dev/null | wc -l)
        if [ "$pam_files" -gt 0 ]; then
            echo "${GREEN}✓${NC} PAM конфигурация: $pam_files файлов"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        fi
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/securetty" ]; then
        local secure_lines=$(wc -l < /etc/securetty)
        echo "${GREEN}✓${NC} /etc/securetty: $secure_lines строк"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    TOTAL_TESTS=$((TOTAL_TESTS + tests))
    echo "Выполнено тестов: $tests"
}

run_accounting_tests() {
    local tests=0
    
    if command -v auditctl >/dev/null 2>&1; then
        if auditctl -l 2>/dev/null | grep -q .; then
            local audit_rules=$(auditctl -l 2>/dev/null | wc -l)
            echo "${GREEN}✓${NC} Audit правил: $audit_rules"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo "${YELLOW}⚠${NC} Audit правила не настроены"
            WARNING_TESTS=$((WARNING_TESTS + 1))
        fi
        tests=$((tests + 1))
    fi
    
    if systemctl is-active auditd 2>/dev/null | grep -q "active"; then
        echo "${GREEN}✓${NC} auditd активен"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    elif ps aux | grep -q "[a]uditd"; then
        echo "${GREEN}✓${NC} auditd процесс работает"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "${YELLOW}⚠${NC} auditd не активен"
        WARNING_TESTS=$((WARNING_TESTS + 1))
    fi
    tests=$((tests + 1))
    
    if [ -f "/etc/audit/auditd.conf" ]; then
        echo "${GREEN}✓${NC} Файл auditd.conf найден"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -d "/var/log/audit" ]; then
        local audit_logs=$(ls /var/log/audit/ 2>/dev/null | wc -l)
        echo "${GREEN}✓${NC} Логов audit: $audit_logs файлов"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -f "/var/log/wtmp" ]; then
        local wtmp_size=$(stat -c '%s' /var/log/wtmp 2>/dev/null)
        echo "${GREEN}✓${NC} wtmp размер: $((wtmp_size/1024)) KB"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    TOTAL_TESTS=$((TOTAL_TESTS + tests))
    echo "Выполнено тестов: $tests"
}

run_boot_tests() {
    local tests=0
    
    if [ -f "/boot/grub/grub.cfg" ]; then
        local grub_owner=$(stat -c '%U' /boot/grub/grub.cfg 2>/dev/null)
        if [ "$grub_owner" = "root" ]; then
            echo "${GREEN}✓${NC} grub.cfg владелец: $grub_owner"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo "${RED}✗${NC} grub.cfg владелец: $grub_owner"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/default/grub" ]; then
        echo "${GREEN}✓${NC} Файл /etc/default/grub найден"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local running_services=$(systemctl list-units --type=service --state=running 2>/dev/null | wc -l)
    if [ "$running_services" -gt 0 ]; then
        echo "${GREEN}✓${NC} Активных служб: $running_services"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local enabled_services=$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | wc -l)
    if [ "$enabled_services" -gt 0 ]; then
        echo "${GREEN}✓${NC} Включенных служб: $enabled_services"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/inittab" ] || [ -d "/etc/systemd/system" ]; then
        echo "${GREEN}✓${NC} Система инициализации определена"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local boot_time=$(who -b 2>/dev/null | awk '{print $3, $4}')
    if [ -n "$boot_time" ]; then
        echo "${GREEN}✓${NC} Время загрузки: $boot_time"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    TOTAL_TESTS=$((TOTAL_TESTS + tests))
    echo "Выполнено тестов: $tests"
}

run_kernel_tests() {
    local tests=0
    
    local kernel_version=$(uname -r)
    echo "${GREEN}✓${NC} Версия ядра: $kernel_version"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    if [ -f "/proc/sys/kernel/randomize_va_space" ]; then
        local aslr=$(cat /proc/sys/kernel/randomize_va_space)
        if [ "$aslr" -ge 1 ]; then
            echo "${GREEN}✓${NC} ASLR: $aslr"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo "${RED}✗${NC} ASLR: $aslr"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
        tests=$((tests + 1))
    fi
    
    if [ -f "/proc/sys/net/ipv4/icmp_echo_ignore_all" ]; then
        local icmp_ignore=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_all)
        echo "${GREEN}✓${NC} ICMP ignore: $icmp_ignore"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -f "/proc/sys/net/ipv4/ip_forward" ]; then
        local ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)
        echo "${GREEN}✓${NC} IP forward: $ip_forward"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local loaded_modules=$(lsmod | wc -l)
    echo "${GREEN}✓${NC} Загруженных модулей: $loaded_modules"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    if [ -f "/etc/sysctl.conf" ]; then
        local sysctl_lines=$(wc -l < /etc/sysctl.conf)
        echo "${GREEN}✓${NC} sysctl.conf строк: $sysctl_lines"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    TOTAL_TESTS=$((TOTAL_TESTS + tests))
    echo "Выполнено тестов: $tests"
}

run_filesystem_tests() {
    local tests=0
    
    local mounts=$(mount | wc -l)
    echo "${GREEN}✓${NC} Точки монтирования: $mounts"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    if df -h / >/dev/null 2>&1; then
        local root_usage=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
        echo "${GREEN}✓${NC} Занято на /: $root_usage%"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/fstab" ]; then
        local fstab_entries=$(grep -v '^#' /etc/fstab | grep -v '^$' | wc -l)
        echo "${GREEN}✓${NC} fstab записей: $fstab_entries"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local tmp_noexec=$(mount | grep '/tmp' | grep -q 'noexec' && echo "yes" || echo "no")
    echo "${GREEN}✓${NC} /tmp noexec: $tmp_noexec"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    if findmnt /home >/dev/null 2>&1; then
        echo "${GREEN}✓${NC} /home отдельный раздел"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "${YELLOW}⚠${NC} /home не отдельный раздел"
        WARNING_TESTS=$((WARNING_TESTS + 1))
    fi
    tests=$((tests + 1))
    
    local disk_count=$(lsblk 2>/dev/null | grep 'disk' | wc -l)
    if [ "$disk_count" -gt 0 ]; then
        echo "${GREEN}✓${NC} Дисков: $disk_count"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    TOTAL_TESTS=$((TOTAL_TESTS + tests))
    echo "Выполнено тестов: $tests"
}

run_firewall_tests() {
    local tests=0
    
    if command -v ufw >/dev/null 2>&1; then
        ufw_status_output=$(ufw status 2>/dev/null)
        if echo "$ufw_status_output" | grep -q "Status: active"; then
            ufw_rules=$(ufw status numbered 2>/dev/null | grep -c '^\[.*\]' 2>/dev/null || echo 0)
            if [ "$ufw_rules" -gt 0 ]; then
                echo "${GREEN}✓${NC} UFW активен, правил: $ufw_rules"
            else
                echo "${GREEN}✓${NC} UFW активен"
            fi
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo "${YELLOW}⚠${NC} UFW не активен"
            WARNING_TESTS=$((WARNING_TESTS + 1))
        fi
        tests=$((tests + 1))
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall_state=$(firewall-cmd --state 2>/dev/null)
        if echo "$firewall_state" | grep -q "running"; then
            echo "${GREEN}✓${NC} firewalld активен"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo "${YELLOW}⚠${NC} firewalld не активен"
            WARNING_TESTS=$((WARNING_TESTS + 1))
        fi
        tests=$((tests + 1))
    elif command -v iptables >/dev/null 2>&1; then
        iptables_rules=$(iptables -L 2>/dev/null | grep -c '^ACCEPT\|^DROP\|^REJECT')
        echo "${GREEN}✓${NC} iptables правил: $iptables_rules"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    else
        echo "${YELLOW}⚠${NC} Фаервол не найден"
        WARNING_TESTS=$((WARNING_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/default/ufw" ]; then
        echo "${GREEN}✓${NC} Файл ufw config найден"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local listening_ports=$(ss -tuln 2>/dev/null | grep -c LISTEN)
    echo "${GREEN}✓${NC} Прослушиваемых портов: $listening_ports"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    if [ -f "/etc/services" ]; then
        local services_count=$(wc -l < /etc/services)
        echo "${GREEN}✓${NC} Известных сервисов: $services_count"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    ip6tables_rules=$(ip6tables -L 2>/dev/null | grep -c '^ACCEPT\|^DROP\|^REJECT' 2>/dev/null || echo 0)
    echo "${GREEN}✓${NC} ip6tables правил: $ip6tables_rules"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    TOTAL_TESTS=$((TOTAL_TESTS + tests))
    echo "Выполнено тестов: $tests"
}

run_networking_tests() {
    local tests=0
    
    local interfaces=$(ip link show 2>/dev/null | grep -c '^[0-9]:')
    echo "${GREEN}✓${NC} Сетевых интерфейсов: $interfaces"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    local ip_addr=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -n "$ip_addr" ]; then
        echo "${GREEN}✓${NC} IP адрес: $ip_addr"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/hosts" ]; then
        local hosts_entries=$(grep -v '^#' /etc/hosts | grep -v '^$' | wc -l)
        echo "${GREEN}✓${NC} hosts записей: $hosts_entries"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/resolv.conf" ]; then
        local dns_servers=$(grep '^nameserver' /etc/resolv.conf | wc -l)
        echo "${GREEN}✓${NC} DNS серверов: $dns_servers"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/nsswitch.conf" ]; then
        echo "${GREEN}✓${NC} nsswitch.conf найден"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local established_conn=$(ss -tun state established 2>/dev/null | wc -l)
    echo "${GREEN}✓${NC} Установленных соединений: $established_conn"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    TOTAL_TESTS=$((TOTAL_TESTS + tests))
    echo "Выполнено тестов: $tests"
}

run_logging_tests() {
    local tests=0
    
    if [ -d "/var/log" ]; then
        local log_files=$(find /var/log -type f -name "*.log" 2>/dev/null | wc -l)
        echo "${GREEN}✓${NC} Лог файлов: $log_files"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -f "/var/log/syslog" ] || [ -f "/var/log/messages" ]; then
        echo "${GREEN}✓${NC} Системный лог найден"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/rsyslog.conf" ] || [ -f "/etc/syslog.conf" ]; then
        echo "${GREEN}✓${NC} Конфиг syslog найден"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local auth_log=$(ls /var/log/auth.log /var/log/secure 2>/dev/null | head -1)
    if [ -f "$auth_log" ]; then
        local auth_size=$(stat -c '%s' "$auth_log" 2>/dev/null)
        echo "${GREEN}✓${NC} Лог аутентификации: $((auth_size/1024)) KB"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/logrotate.conf" ]; then
        echo "${GREEN}✓${NC} logrotate.conf найден"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local journal_entries=$(journalctl --quiet 2>/dev/null | tail -5 | wc -l)
    if [ "$journal_entries" -gt 0 ]; then
        echo "${GREEN}✓${NC} journalctl доступен"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    TOTAL_TESTS=$((TOTAL_TESTS + tests))
    echo "Выполнено тестов: $tests"
}

run_malware_tests() {
    local tests=0
    
    if command -v clamscan >/dev/null 2>&1; then
        echo "${GREEN}✓${NC} ClamAV установлен"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if command -v rkhunter >/dev/null 2>&1; then
        echo "${GREEN}✓${NC} rkhunter установлен"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if command -v chkrootkit >/dev/null 2>&1; then
        echo "${GREEN}✓${NC} chkrootkit установлен"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local cron_dirs="/etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly"
    local cron_count=0
    for dir in $cron_dirs; do
        if [ -d "$dir" ]; then
            cron_count=$((cron_count + $(ls "$dir" 2>/dev/null | wc -l)))
        fi
    done
    echo "${GREEN}✓${NC} Cron заданий: $cron_count"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    local user_crons=$(crontab -l 2>/dev/null | grep -v '^#' | wc -l)
    echo "${GREEN}✓${NC} Пользовательских cron: $user_crons"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    local suspicious_procs=$(ps aux 2>/dev/null | grep -E '(miner|backdoor|malware)' | grep -v grep | wc -l)
    if [ "$suspicious_procs" -eq 0 ]; then
        echo "${GREEN}✓${NC} Подозрительных процессов: 0"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "${RED}✗${NC} Подозрительных процессов: $suspicious_procs"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    tests=$((tests + 1))
    
    TOTAL_TESTS=$((TOTAL_TESTS + tests))
    echo "Выполнено тестов: $tests"
}

run_ssh_tests() {
    local tests=0
    
    if [ -f "/etc/ssh/sshd_config" ]; then
        echo "${GREEN}✓${NC} sshd_config найден"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
        
        local ssh_port=$(grep -i "^Port" /etc/ssh/sshd_config | awk '{print $2}' | head -1)
        if [ -n "$ssh_port" ]; then
            echo "${GREEN}✓${NC} SSH порт: $ssh_port"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo "${YELLOW}⚠${NC} SSH порт по умолчанию (22)"
            WARNING_TESTS=$((WARNING_TESTS + 1))
        fi
        tests=$((tests + 1))
        
        if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
            local root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}' | head -1)
            if [ "$root_login" = "no" ] || [ "$root_login" = "prohibit-password" ]; then
                echo "${GREEN}✓${NC} Root login: $root_login"
                PASSED_TESTS=$((PASSED_TESTS + 1))
            else
                echo "${RED}✗${NC} Root login: $root_login"
                FAILED_TESTS=$((FAILED_TESTS + 1))
            fi
        else
            echo "${YELLOW}⚠${NC} PermitRootLogin не указан"
            WARNING_TESTS=$((WARNING_TESTS + 1))
        fi
        tests=$((tests + 1))
        
        if grep -q "^PasswordAuthentication" /etc/ssh/sshd_config; then
            local pass_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}' | head -1)
            if [ "$pass_auth" = "no" ]; then
                echo "${GREEN}✓${NC} Password auth: $pass_auth"
                PASSED_TESTS=$((PASSED_TESTS + 1))
            else
                echo "${YELLOW}⚠${NC} Password auth: $pass_auth"
                WARNING_TESTS=$((WARNING_TESTS + 1))
            fi
        fi
        tests=$((tests + 1))
        
        local ssh_keys=$(find /etc/ssh -name "*pub" 2>/dev/null | wc -l)
        echo "${GREEN}✓${NC} SSH ключей: $ssh_keys"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    else
        echo "${YELLOW}⚠${NC} sshd_config не найден"
        WARNING_TESTS=$((WARNING_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local ssh_process=$(ps aux | grep -E '(sshd|ssh-daemon)' | grep -v grep | wc -l)
    echo "${GREEN}✓${NC} SSH процессов: $ssh_process"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    TOTAL_TESTS=$((TOTAL_TESTS + tests))
    echo "Выполнено тестов: $tests"
}

run_time_tests() {
    local tests=0
    
    if command -v timedatectl >/dev/null 2>&1; then
        local time_sync=$(timedatectl status | grep -i "ntp synchronized" | grep -i "yes")
        if [ -n "$time_sync" ]; then
            echo "${GREEN}✓${NC} NTP синхронизация: да"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo "${YELLOW}⚠${NC} NTP синхронизация: нет"
            WARNING_TESTS=$((WARNING_TESTS + 1))
        fi
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/chrony.conf" ] || [ -f "/etc/ntp.conf" ]; then
        echo "${GREEN}✓${NC} Конфиг NTP найден"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local current_time=$(date +"%Y-%m-%d %H:%M:%S %Z")
    echo "${GREEN}✓${NC} Текущее время: $current_time"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    local timezone=$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null)
    if [ -n "$timezone" ]; then
        echo "${GREEN}✓${NC} Часовой пояс: $timezone"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/adjtime" ]; then
        echo "${GREEN}✓${NC} Файл adjtime найден"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local uptime_days=$(uptime | awk -F'( |,|:)+' '{print $6}')
    echo "${GREEN}✓${NC} Аптайм дней: $uptime_days"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    TOTAL_TESTS=$((TOTAL_TESTS + tests))
    echo "Выполнено тестов: $tests"
}

run_hardening_tests() {
    local tests=0
    
    if [ -f "/usr/sbin/sestatus" ]; then
        local selinux_status=$(sestatus 2>/dev/null | grep "SELinux status" | grep "enabled")
        if [ -n "$selinux_status" ]; then
            echo "${GREEN}✓${NC} SELinux включен"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        fi
        tests=$((tests + 1))
    elif [ -f "/usr/sbin/apparmor_status" ]; then
        local apparmor_status=$(apparmor_status 2>/dev/null | grep "apparmor module is loaded")
        if [ -n "$apparmor_status" ]; then
            echo "${GREEN}✓${NC} AppArmor включен"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        fi
        tests=$((tests + 1))
    fi
    
    if [ -f "/proc/sys/kernel/randomize_va_space" ]; then
        local aslr=$(cat /proc/sys/kernel/randomize_va_space)
        if [ "$aslr" -ge 1 ]; then
            echo "${GREEN}✓${NC} ASLR значение: $aslr"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo "${RED}✗${NC} ASLR значение: $aslr"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
        tests=$((tests + 1))
    fi
    
    if [ -f "/proc/sys/kernel/exec-shield" ]; then
        local exec_shield=$(cat /proc/sys/kernel/exec-shield)
        echo "${GREEN}✓${NC} Exec-shield: $exec_shield"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local suid_files=$(find / -type f -perm -4000 2>/dev/null | wc -l)
    echo "${GREEN}✓${NC} SUID файлов: $suid_files"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    local sgid_files=$(find / -type f -perm -2000 2>/dev/null | wc -l)
    echo "${GREEN}✓${NC} SGID файлов: $sgid_files"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    tests=$((tests + 1))
    
    TOTAL_TESTS=$((TOTAL_TESTS + tests))
    echo "Выполнено тестов: $tests"
}

run_shells_tests() {
    local tests=0
    
    if [ -f "/etc/shells" ]; then
        echo "${GREEN}✓${NC} Файл /etc/shells найден"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
        
        local shells_count=$(wc -l < /etc/shells)
        echo "${GREEN}✓${NC} Доступных оболочек: $shells_count"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    else
        echo "${YELLOW}⚠${NC} Файл /etc/shells не найден"
        WARNING_TESTS=$((WARNING_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/profile" ]; then
        echo "${GREEN}✓${NC} Файл /etc/profile найден"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    if [ -f "/etc/bash.bashrc" ]; then
        echo "${GREEN}✓${NC} Файл bash.bashrc найден"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local user_shell=$(getent passwd $USER | cut -d: -f7)
    if [ -n "$user_shell" ]; then
        echo "${GREEN}✓${NC} Текущая оболочка: $user_shell"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    local histfile="${HISTFILE:-$HOME/.bash_history}"
    if [ -f "$histfile" ]; then
        local hist_size=$(stat -c '%s' "$histfile" 2>/dev/null)
        echo "${GREEN}✓${NC} История bash: $((hist_size/1024)) KB"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        tests=$((tests + 1))
    fi
    
    TOTAL_TESTS=$((TOTAL_TESTS + tests))
    echo "Выполнено тестов: $tests"
}

run_file_perm_tests() {
    local tests=0
    
    CRITICAL_FILES="/etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config /etc/hosts.allow /etc/hosts.deny"
    
    for file in $CRITICAL_FILES; do
        if [ -f "$file" ]; then
            local perms=$(stat -c '%a' "$file" 2>/dev/null)
            local owner=$(stat -c '%U' "$file" 2>/dev/null)
            
            if [ "$owner" = "root" ]; then
                echo "${GREEN}✓${NC} $file: владелец root"
                PASSED_TESTS=$((PASSED_TESTS + 1))
            else
                echo "${RED}✗${NC} $file: владелец $owner"
                FAILED_TESTS=$((FAILED_TESTS + 1))
            fi
            tests=$((tests + 1))
            
            case "$file" in
                /etc/shadow)
                    if [ "$perms" -le 640 ]; then
                        echo "${GREEN}✓${NC} $file: права $perms"
                        PASSED_TESTS=$((PASSED_TESTS + 1))
                    else
                        echo "${RED}✗${NC} $file: права $perms"
                        FAILED_TESTS=$((FAILED_TESTS + 1))
                    fi
                    ;;
                /etc/sudoers)
                    if [ "$perms" -le 440 ]; then
                        echo "${GREEN}✓${NC} $file: права $perms"
                        PASSED_TESTS=$((PASSED_TESTS + 1))
                    else
                        echo "${YELLOW}⚠${NC} $file: права $perms"
                        WARNING_TESTS=$((WARNING_TESTS + 1))
                    fi
                    ;;
                *)
                    if [ "$perms" -le 644 ]; then
                        echo "${GREEN}✓${NC} $file: права $perms"
                        PASSED_TESTS=$((PASSED_TESTS + 1))
                    else
                        echo "${YELLOW}⚠${NC} $file: права $perms"
                        WARNING_TESTS=$((WARNING_TESTS + 1))
                    fi
                    ;;
            esac
            tests=$((tests + 1))
        fi
    done
    
    local world_writable=$(find / -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -5 | wc -l)
    if [ "$world_writable" -eq 0 ]; then
        echo "${GREEN}✓${NC} World-writable файлов: 0"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "${YELLOW}⚠${NC} World-writable файлов: $world_writable"
        WARNING_TESTS=$((WARNING_TESTS + 1))
    fi
    tests=$((tests + 1))
    
    local noowner_files=$(find / -nouser 2>/dev/null | head -3 | wc -l)
    if [ "$noowner_files" -eq 0 ]; then
        echo "${GREEN}✓${NC} Файлов без владельца: 0"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "${YELLOW}⚠${NC} Файлов без владельца: $noowner_files"
        WARNING_TESTS=$((WARNING_TESTS + 1))
    fi
    tests=$((tests + 1))
    
    TOTAL_TESTS=$((TOTAL_TESTS + tests))
    echo "Выполнено тестов: $tests"
}

case "${1:-}" in
    ""|"audit")
        run_vps_modules
        ;;
    "help"|"--help"|"-h")
        echo "Использование: $0 [команда]"
        echo ""
        echo "Команды:"
        echo "  audit     - Запуск полного аудита (по умолчанию)"
        echo "  help      - Показать эту справку"
        echo ""
        echo "Модули аудита:"
        echo "  authentication    - Аутентификация"
        echo "  accounting        - Учет и аудит"
        echo "  boot_services     - Загрузка и службы"
        echo "  kernel            - Параметры ядра"
        echo "  filesystems       - Файловые системы"
        echo "  firewalls         - Межсетевые экраны"
        echo "  networking        - Сетевая конфигурация"
        echo "  logging           - Логирование"
        echo "  malware           - Защита от вредоносного ПО"
        echo "  ssh               - Конфигурация SSH"
        echo "  time              - Синхронизация времени"
        echo "  hardening         - Усиление безопасности"
        echo "  shells            - Безопасность оболочек"
        echo "  file_permissions  - Права доступа к файлам"
        ;;
    *)
        echo "Неизвестная команда: $1"
        echo "Используйте: $0 help"
        exit 1
        ;;
esac
