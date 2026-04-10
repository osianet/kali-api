FROM kalilinux/kali-rolling

# Install tools and Python in one layer, clean up apt lists
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        whois \
        dnsutils \
        iputils-ping \
        traceroute \
        curl \
        nikto \
        theharvester \
        whatweb \
        sslscan \
        amass \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
