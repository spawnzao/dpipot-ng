#!/bin/bash

# Organizações globais convincentes
ORGS=(
    "Nexus Systems" "BlueWave Technologies" "Meridian Solutions"
    "Corelink IT" "Vantage Networks" "Pinnacle Data Services"
    "Horizon Cloud" "Stratus Technologies" "Orbital Systems"
    "Apex Digital" "Luminary Networks" "Catalyst IT Solutions"
)

# Domínios sem referência regional
DOMAINS=(
    "mail.nexussys.com" "smtp.bluewave.net" "imap.meridian-solutions.com"
    "webmail.corelink.io" "mail.vantage-networks.com" "smtp.pinnacledata.net"
    "imap.horizoncloud.com" "mail.stratus-tech.com" "webmail.orbitalsys.net"
    "smtp.apexdigital.com" "mail.luminarynet.io" "imap.catalyst-it.com"
)

# Cidades do mundo
CITIES=(
    "Amsterdam" "Singapore" "Frankfurt" "Toronto" "Stockholm"
    "Zurich" "Dublin" "Tokyo" "Sydney" "London"
    "Helsinki" "Vienna"
)

# Estados/regiões correspondentes
STATES=(
    "North Holland" "Central Region" "Hesse" "Ontario" "Stockholm County"
    "Zurich" "Leinster" "Tokyo" "New South Wales" "England"
    "Uusimaa" "Vienna"
)

# Países correspondentes (código ISO)
COUNTRIES=(
    "NL" "SG" "DE" "CA" "SE"
    "CH" "IE" "JP" "AU" "GB"
    "FI" "AT"
)

# Sorteia índice aleatório
IDX=$((RANDOM % ${#ORGS[@]}))

ORG="${ORGS[$IDX]}"
DOMAIN="${DOMAINS[$IDX]}"
CITY="${CITIES[$IDX]}"
STATE="${STATES[$IDX]}"
COUNTRY="${COUNTRIES[$IDX]}"

echo "Gerando certificado para: $DOMAIN"
echo "  Org    : $ORG"
echo "  Local  : $CITY / $STATE / $COUNTRY"

openssl req -x509 -newkey rsa:4096 \
  -keyout key.pem -out cert.pem \
  -days 1825 \
  -nodes \
  -subj "/CN=${DOMAIN}/O=${ORG}/C=${COUNTRY}/ST=${STATE}/L=${CITY}/OU=IT"

echo ""
echo "Certificado gerado:"
openssl x509 -in cert.pem -text -noout | grep -A6 "Subject:"
