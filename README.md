Welcome to the Travel Log website
This is Project 3 - Item Catalog 
Version : 1.0.0
Author : Timothee Hack
==================================================================


PREREQUISITES :
---------------------

This program requires the installation of a preconfigured Virtual Machine provided by Udacity.
To make sure you have everything set up correctly, please follow the steps outlined in this link :
https://www.udacity.com/wiki/ud088/vagrant

Some additional python modules are required to run this application. Please follow the installation steps carefully.


INSTALLATION :
---------------------

1) Install the contents of this project into the folder linked to your vagrant installation. This will automatically copy the contents into the VM.
2) Log into Vagrant using a command shell and the command "Vagrant ssh"
3) Run the following commands to install prerequisites
	3.1)	sudo -y apt-get install python-dev
	3.2)	sudo -y apt-get install libjpeg8-dev 
	3.3)	sudo pip install Pillow
4) Go into the "vagrant" folder using "cd /vagrant"
5) Run the command "python database_setup.py"
6) Run the command "python load_sample_data.py"
7) Install is now complete.


RUNNING THE PROGRAM : 
---------------------

To run the program, follow the following steps :
1) Log into Vagrant using a command shell and the command "Vagrant ssh"
2) Go into the "vagrant" folder using "cd /vagrant"
3) Run the project using the command "python project.py"
4) Open a web browser and go to the the address "http://localhost:5000/"


API ENDPOINTS (JSON) : 
---------------------
The Travel Log app provides an API of JSON endpoints. Here is the list :
	/region/JSON
	Returns the list of travel logs
	
	/region/<region_id>/place/JSON
	Returns the contents of a given travel logs
	
	/region/<region_id>/place/<place_id>/JSON
	Returns a specific entry for a given travel log
	