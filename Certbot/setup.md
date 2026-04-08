# Certbot setup
*prerequisite: you will need a site up and running online on port 80 and on a machine you can connect to via ssh*
*note: this is the setup for a SafeLine WAF/Gunicorn web server setup on a Debian based OS. Other server/OS combinations will have different setups and can be found on certbot's website*

#### **Install Dependencies**
`sudo apt update`
`sudo apt install python3 python3-dev python3-venv libaugeas-dev gcc`

#### **Remove certbot-auto and CertbotOS, if installed**
check if installed
`apt list --installed | grep -i certbot`

#### **Setup a Python Virtual Environment**
`sudo python3 -m venv /opt/certbot/`
`sudo /opt/certbot/bin/pip install --upgrade pip`

#### **Install Certbot**
`sudo /opt/certbot/bin/pip install certbot`

#### **Ensure Certbot Can Be Run in Command Line**
`sudo ln -s /opt/certbot/bin/certbot /usr/local/bin/certbot`

#### **Run Cerbot**
First, turn off webserver

run:
`sudo certbot certonly --standalone`
*Certbot will spin a temporary server*

#### **Install Certificate**
in this setup the certificate will be put into SafeLineWAF when configuring the webapp.

#### **Restart Webserver**
`sudo docker run -p 80:8081 -d magic-meme-ball:latest`

#### **Setup Automatic Renewal**
sets up a cron job to renew your certificate automatically
`echo "0 0,12 * * * root /opt/certbot/bin/python -c 'import random; import time; time.sleep(random.random() * 3600)' && sudo certbot renew -q" | sudo tee -a /etc/crontab > /dev/null`

#### **Monthly Update Certbot**
`sudo /opt/certbot/bin/pip install --upgrade certbot`