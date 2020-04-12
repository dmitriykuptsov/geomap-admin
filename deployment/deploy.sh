#!/bin/bash

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
cd $SCRIPTPATH/../
git pull
sudo mkdir -p /opt/geomap-admin/
sudo mkdir -p /opt/geomap-admin/templates
sudo rsync -rv ./templates/* /opt/geomap-admin/templates/
sudo rsync -rv ./static/* /opt/geomap-admin/static
sudo rsync -rv *.py /opt/geomap-admin/
sudo chown www-data:www-data -R /opt/geomap-admin/
sudo rsync -rv deployment/systemd/geoapi-admin.service /etc/systemd/system
sudo systemctl enable geoapi-admin
sudo systemctl daemon-reload
sudo service geoapi-admin restart
#echo "The server is accessable @ http://localhost:5001/"
