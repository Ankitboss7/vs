#!/usr/bin/env bash
set -euo pipefail

# Multi IPv4 VPS Creator (Docker-based)
# Made by PowerDev / GPT-5
# Creates 10 Ubuntu mini VPS each with its own public IPv4 and random root password

IMAGE_NAME="multi-vps:ubuntu-sshd"
CONTAINER_PREFIX="vps"
RESULT_CSV="vps_list.csv"
HOST_IFACE="eth0"
IPS_FILE="ips.txt"
NUM=10

echo "🔄 [1/8] System update & install dependencies..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
apt-get install -y curl ca-certificates gnupg lsb-release iproute2 openssl net-tools

# Install Docker if missing
if ! command -v docker >/dev/null 2>&1; then
  echo "🐳 Installing Docker..."
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io
else
  echo "✅ Docker already installed."
fi

# Check IP list
if [ ! -f "$IPS_FILE" ]; then
  echo "❌ ips.txt not found. Create it with 10 IPv4 addresses (one per line)."
  exit 1
fi

mapfile -t IPS < <(grep -v '^#' "$IPS_FILE" | grep -v '^\s*$' || true)
if [ "${#IPS[@]}" -ne "$NUM" ]; then
  echo "❌ Found ${#IPS[@]} IPs in ips.txt (expected $NUM)."
  exit 1
fi

echo "✅ Loaded ${#IPS[@]} IPs from $IPS_FILE"

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Build Docker image
echo "🛠️ [2/8] Building Docker image..."
cat > Dockerfile.mini <<'EOF'
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y openssh-server && \
    mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "export VISIBLE=now" >> /etc/profile && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
EOF

docker build -t "$IMAGE_NAME" -f Dockerfile.mini .
rm -f Dockerfile.mini

# Create result CSV
echo "container,public_ip,container_ip,password" > "$RESULT_CSV"

echo "🚀 [3/8] Launching containers..."

for i in $(seq 1 $NUM); do
  name="${CONTAINER_PREFIX}${i}"
  pub_ip="${IPS[$((i-1))]}"
  PASS=$(openssl rand -base64 12)

  echo "⚙️ Creating $name with IP $pub_ip ..."
  cid=$(docker run -d --name "$name" "$IMAGE_NAME")
  sleep 2

  docker exec "$name" bash -c "echo root:${PASS} | chpasswd"
  c_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$cid")

  # Assign IP alias
  ip addr add ${pub_ip}/32 dev "$HOST_IFACE" 2>/dev/null || true

  # Setup NAT (public IP → container)
  iptables -t nat -A PREROUTING -d ${pub_ip} -p tcp --dport 22 -j DNAT --to-destination ${c_ip}:22
  iptables -t nat -A POSTROUTING -s ${c_ip} -j MASQUERADE

  echo "${name},${pub_ip},${c_ip},${PASS}" >> "$RESULT_CSV"

  echo "✅ $name ready: ssh root@${pub_ip} (password: ${PASS})"
done

echo "💾 [4/8] Installing iptables-persistent..."
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
iptables-save > /etc/iptables/rules.v4

echo "🔐 [5/8] Optional: Adding SSH key support (skip if no key found)"
if [ -f ~/.ssh/id_rsa.pub ]; then
  PUBKEY=$(cat ~/.ssh/id_rsa.pub)
  for i in $(seq 1 $NUM); do
    name="${CONTAINER_PREFIX}${i}"
    docker exec "$name" bash -c "mkdir -p /root/.ssh && echo '$PUBKEY' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"
  done
  echo "✅ Public key added to all VPS."
else
  echo "⚠️ No SSH key found (~/.ssh/id_rsa.pub missing). Using passwords only."
fi

echo "🧾 [6/8] VPS List created: $RESULT_CSV"
column -t -s, "$RESULT_CSV" || cat "$RESULT_CSV"

echo "⚙️ [7/8] Enabling auto-restart for containers..."
docker update --restart unless-stopped $(docker ps -aq)

echo "🧱 [8/8] Finalizing..."

echo
echo "✅ All 10 mini-VPS created successfully!"
echo "File saved: $RESULT_CSV"
echo
echo "Example login:"
echo "   ssh root@${IPS[0]}"
echo "   (password inside vps_list.csv)"
echo
echo "To list containers: docker ps --format '{{.Names}} -> {{.Status}}'"
echo "To stop/start: docker stop vps1 ; docker start vps1"
echo
echo "💡 Tip: To auto-delete later: docker rm -f vps{1..10}"
echo
echo "🎉 DONE — Multi IPv4 VPS setup complete!"
