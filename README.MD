This app is based on Python flask and shows how to deploy to a remote server in this case, Amazon Lightsail instance. Based off of the Udacity Fullstack web nanodegree.


The app can be accessed from http://35.178.28.147 || http://ec2-35-178-28-147.eu-west-2.compute.amazonaws.com

### SETUP REQUIREMENTS
* A modern web browser
* [Amazon Lightsail Ubuntu Instance](https://lightsail.aws.amazon.com/ls/webapp)
* Vagrant
* VirtualBox
* Ubuntu Linux Virtual Machine


P.S: If you already are on a Linux OS, the last 3 requirements are optional.

## The Setup Process

#### SETUP SSH KEYS
SSH keys are generally more secure than password login. [Details here.](https://www.e2enetworks.com/help/knowledge-base/why-key-based-ssh-is-secure-than-password-based-access/)
* Generate an ssh-key pair on your local machine with ```ssh-keygen```
* Upload the public key to the ~/.ssh/authorized_keys file

Login on your local machine as grader with: ``` sudo ssh -i ~/.ssh/<your-private-key>.pem grader@35.178.28.147```

Set timezone: ```sudo timedatectl set-timezone UTC```

Verify timezone with ```timedatectl```

### SET UP UFW FIREWALL
```
sudo ufw default deny incoming
sudo ufw allow 2200/tcp
sudo ufw allow 80/tcp
sudo ufw allow 123/tcp
sudo ufw allow www
sudo ufw allow ssh
```

* Type ```sudo nano /etc/hosts,``` add newline underneath localhost line and write <your-public-ip>:ubuntu

* Install Apache2 for the instance with: ```sudo apt-get install apache2```

* Check that Apache2 is loaded at the Static/Public IP, hit your browser with <your-public-ip>. It should show the ubuntu homepage.

* Install mod-wsgi to allow you to run wsgi files: ```sudo apt-get install libapache2-mod-wsgi```

### Create Configuration Files
The config files is checked first when a request is made. It's like the usher into your application. It hands over control to your wsgi file which then hands control to your application.

Go to the sites-enabled directory in apache2:
cd ```/etc/apache2/sites-enabled/```

Create and edit the 000-default.conf file: ```sudo nano 000-default.conf```

Add in the following line before : WSGIScriptAlias ``` / /var/www/html/myapp.wsgi```


Create a ```catalog.conf``` file and add the contents and edit the addresses to match yours:

```
<VirtualHost *:80>
    ServerName 35.177.223.179
    ServerAlias ec2-35-177-223-179.eu-west-2.compute.amazonaws.com
    ServerAdmin admin@35.177.223.179
     WSGIDaemonProcess catalog user=www-data group=www-data threads=5 home=/var/www/catalog/
    WSGIProcessGroup catalog
    WSGIScriptAlias / /var/www/catalog/catalog.wsgi
    <Directory /var/www/catalog/catalog/>
        Order allow,deny
        Allow from all
    </Directory>
    Alias /static /var/www/catalog/catalog/static
    <Directory /var/www/catalog/catalog/static/>
        Order allow,deny
        Allow from all
    </Directory>
    ErrorLog ${APACHE_LOG_DIR}/error.log
    LogLevel warn
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```


Restart Apache: ```sudo apache2ctl restart```

Install Postgresql : ```sudo apt-get install postgresql postgresql-contrib``` 

P.S: The "contrib" flag just adds additional utilites.

When prompted:
n for super user
y for creating databases and other prompts
db-password for password
Exit postgres account with: ```exit```

*Install and Configure Git*
```sudo apt-get install git```


Side-Note: It is recommended you use the same username and email that you use with github.

Login to grader user with: ```sudo su - grader```
Check that Git is installed with: ```git --version```
Set global username and email: ```sudo git config -global user.name "your_username", 
                               sudo git config -global user.email "your_email@emailhost.com"```

Clone Your Catalog Application to the Instance (while logged as grader):
Move to www directory: ```cd var/www/```
Clone repository into instance: ```sudo git clone https://github.com/<your-awesome-git-username>/<your-catalog-app-repo-name>.git catalog```

### SETUP POSTGRESQL DATABASE
Type ```sudo su postgres```
Move to the var/www/catalog/catalog directory: ```cd var/www/catalog/catalog```

Enter psql with: psql

Type ```CREATE USER catalog;```
Next type ```CREATE DATABASE catalogapp OWNER catalog```
Also do not forget to replace the line in your app.py file like so:

```
engine = create_engine('postgresql://catalogapp:password@localhost/catalog')
Base.metadata.bind = engine
```

Refer to these postgresql docs if you get stuck:

* https://www.postgresql.org/docs/9.0/static/sql-createdatabase.html

* https://www.postgresql.org/docs/9.1/static/app-createdb.html


type ```\q``` to leave psql area and exit to go back to your home directory.

Install necessary packages your flask app need to function:
```
sudo pip install sqlalchemy
sudo pip install python-psycopg2
sudo pip install Flask-SQLAlchemy
sudo pip install oauth2client
sudo pip install --upgrade oauth2client
sudo pip install requests
sudo pip install httplib2
sudo apt-get -qqy install python3 python3-pip
sudo pip3 install --upgrade pip
sudo  pip3 install flask packaging oauth2client 
sudo pip3 install sqlalchemy flask-sqlalchemy psycopg2 requests
```

### Setup up your Google or and Facebook Login
For this you have to go to your google developer account and update the Javascript origin and redirect uris
Example as in my case: ```http://ec2-35-178-28-147.eu-west-2.compute.amazonaws.com``` (JS Origin)
```http://ec2-35-178-28-147.eu-west-2.compute.amazonaws.com/login ```
```http://ec2-35-178-28-147.eu-west-2.compute.amazonaws.com/gconnect``` (REDIRECT URIs)


Also, make to sure to download and update the new client_secret.json file that would be regenerated based on the URI update you just performed.

I found help for the issues I encountered here:
* Error description: [500 Internal Server error](https://discussions.udacity.com/t/apps-runs-on-port-8080-in-remote-server-but-not-on-static-ip/592874)
* Error description:[Invalid Request:Google OAUTH Login](https://discussions.udacity.com/t/solved-configuring-linux-google-oauth-invalid-request/376259/2)
*  Error description: [Permission denied to generate login hint: Google OAUTH Login](https://stackoverflow.com/questions/36020374/google-permission-denied-to-generate-login-hint-for-target-domain-not-on-localh)
* Error description: [Target WSGI cannot be loaded as a python module](https://stackoverflow.com/questions/45420672/target-wsgi-script-cannot-be-loaded-as-python-module-raspberry-pi)

