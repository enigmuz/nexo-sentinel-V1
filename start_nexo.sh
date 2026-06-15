#!/data/data/com.termux/files/usr/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NEXO SENTINEL CTI — Start Script for Pixel 5
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Usage:
#   cd ~/nexo-sentinel-agent
#   bash start_nexo.sh          # Start in background
#   bash start_nexo.sh stop     # Stop all instances
#   bash start_nexo.sh logs     # Tail live logs
#   bash start_nexo.sh status   # Check if running
#   bash start_nexo.sh update   # Pull latest + restart

set -e

PROJECT_DIR="$HOME/nexo-sentinel-agent"
LOG_DIR="$PROJECT_DIR/logs"
LOG_FILE="$LOG_DIR/nexo.log"
PID_FILE="$LOG_DIR/nexo.pid"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════╗"
    echo "║   🔐 NEXO SENTINEL CTI SYSTEM v4         ║"
    echo "║   iocextract + DeepSeek Hybrid Pipeline   ║"
    echo "╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
}

stop_nexo() {
    echo -e "${YELLOW}[*] Stopping all Nexo processes...${NC}"
    pkill -9 -f "nexo_backend.main" 2>/dev/null || true
    killall python3 2>/dev/null || true
    sleep 3
    # Verify
    if pgrep -f "nexo_backend.main" > /dev/null 2>&1; then
        echo -e "${RED}[!] Some processes still running, force killing...${NC}"
        pkill -9 -f python3 2>/dev/null || true
        sleep 2
    fi
    rm -f "$PID_FILE"
    echo -e "${GREEN}[✓] All Nexo processes stopped${NC}"
}

start_nexo() {
    print_banner
    cd "$PROJECT_DIR"
    mkdir -p "$LOG_DIR"

    # Kill any existing instances
    stop_nexo

    # Check dependencies
    echo -e "${YELLOW}[*] Checking dependencies...${NC}"
    python3 -c "import iocextract" 2>/dev/null || {
        echo -e "${YELLOW}[*] Installing iocextract...${NC}"
        pip install iocextract
    }
    python3 -c "import trafilatura" 2>/dev/null || {
        echo -e "${YELLOW}[*] Installing trafilatura...${NC}"
        pip install trafilatura
    }
    python3 -c "import telegram" 2>/dev/null || {
        echo -e "${YELLOW}[*] Installing python-telegram-bot...${NC}"
        pip install python-telegram-bot
    }

    # Check .env
    if [ ! -f "$PROJECT_DIR/.env" ]; then
        echo -e "${RED}[!] .env file missing! Create it with:${NC}"
        echo "    cp .env.example .env"
        echo "    nano .env"
        exit 1
    fi

    # Start
    echo -e "${YELLOW}[*] Starting Nexo Sentinel...${NC}"
    rm -f "$LOG_FILE"
    nohup python3 -m nexo_backend.main > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    
    echo -e "${GREEN}[✓] Started with PID $(cat $PID_FILE)${NC}"
    echo -e "${CYAN}[*] Waiting for initialization...${NC}"
    sleep 10

    # Check if still running
    if kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo -e "${GREEN}[✓] Nexo Sentinel is running!${NC}"
        echo ""
        echo -e "${CYAN}Commands:${NC}"
        echo "  bash start_nexo.sh logs    — View live logs"
        echo "  bash start_nexo.sh stop    — Stop the bot"
        echo "  bash start_nexo.sh status  — Check status"
        echo "  bash start_nexo.sh update  — Pull latest + restart"
        echo ""
        # Show last few log lines
        tail -5 "$LOG_FILE"
    else
        echo -e "${RED}[!] Failed to start! Check logs:${NC}"
        tail -20 "$LOG_FILE"
        exit 1
    fi
}

show_logs() {
    if [ -f "$LOG_FILE" ]; then
        tail -f "$LOG_FILE"
    else
        echo -e "${RED}[!] No log file found. Is Nexo running?${NC}"
    fi
}

show_status() {
    if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        PID=$(cat "$PID_FILE")
        echo -e "${GREEN}[✓] Nexo Sentinel is RUNNING (PID: $PID)${NC}"
        echo ""
        echo -e "${CYAN}Recent activity:${NC}"
        grep -i 'classified\|complete\|error\|notification\|extract' "$LOG_FILE" 2>/dev/null | tail -10
    else
        echo -e "${RED}[✗] Nexo Sentinel is NOT running${NC}"
    fi
}

update_nexo() {
    echo -e "${YELLOW}[*] Pulling latest code...${NC}"
    cd "$PROJECT_DIR"
    git pull origin master 2>/dev/null || {
        echo -e "${YELLOW}[*] Git pull failed, trying reset...${NC}"
        git fetch origin
        git reset --hard origin/master
    }
    echo -e "${GREEN}[✓] Code updated${NC}"
    
    # Restart
    start_nexo
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Main
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
case "${1:-start}" in
    start)   start_nexo ;;
    stop)    stop_nexo ;;
    logs)    show_logs ;;
    status)  show_status ;;
    update)  update_nexo ;;
    restart) stop_nexo; start_nexo ;;
    *)
        echo "Usage: bash start_nexo.sh [start|stop|logs|status|update|restart]"
        exit 1
        ;;
esac
