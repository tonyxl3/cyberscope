@@ .. @@
 # Instalar dependencias del sistema (INCLUYENDO SSH COMPLETO)
 RUN apt-get update && apt-get install -y \
     curl \
     wget \
     whois \
     dnsutils \
     netcat-traditional \
     openssh-client \
     sshpass \
     net-tools \
     iputils-ping \
     traceroute \
     nmap \
     telnet \
     procps \
+    expect \
     && rm -rf /var/lib/apt/lists/*