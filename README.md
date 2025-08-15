### RDP Broker

Project goal is to combine standalone XRDP servers into one cluster.

A broker is the middle component between the desktops and the RDP servers. The broker need to perform the following tasks:

* Check user credentials.
* Assign users to RDP servers, reconnecting if need be. If a user is already logged into one of the RDP servers and only disconnected, send them back to that same RDP server.
* Load balance the RDP server. If the user is not logged in, send them to the least busy server.


*RDP Broker* works in parallel with XRDP. It makes because:
* Not interfere with original XRDP.
* Test *proof-of-concept*.

*RDP Broker* built on top of libraries  *FreeRDP* и *NNG*.

### Build prerequisite:

**Tested on Debian 13**

```
$ sudo apt install freerdp3-dev libnng-dev

$ git clone https://github.com/AAAPops/rdp-broker.git
$ cd rdp-broker
$ mkdir build && cd build
$ cmake ..
$ make
$ sudo make install

# Default install path is "/usr/local/bin" for Binaries and "/etc/rdp-broker" for Config files.
# To change install path (all will be installed there):

$ cmake -DCMAKE_INSTALL_PREFIX=/opt/rdp-broker ..
```

### Run prerequisite:

```
                                                       192.168.1.121               
                                                          ┌───────────────────────┐
                                                          │            xrdp       │
                 192.168.1.99               ┌────────────►o                       │
                     ┌─────────────────┐    │             │            rdp-agent  │
                     │                 │    │             └───────────────────────┘
xfreerdp client      │                 │    │                                      
      ─────────────► o     rdp-broker  ┼────┤         192.168.1.122                
                     │                 │    │             ┌───────────────────────┐
                     │                 │    │             │            xrdp       │
                     └─────────────────┘    └────────────►o                       │
                                                          │            rdp-agent  │
                                                          └───────────────────────┘
```

1. You have to have 1 or more host with deployed **XRDP** project.
Hosts `129.168.1.121, 192.168.1.122` in the diagram above.

Share the same User's name on all Hosts using local */etc/passwd* or *LDAP*

2. On every such a host with running **xrdp** you need to run **rdp-agent** with config file like:

`/opt/rdp-broker/bin/rdp-agent -f /opt/rdp-broker/etc/rdp-broker/rdp-agent.ini -d`

```
[server]
; tcp://192.168.1.99:5555, tcp://127.0.0.1:5555, tcp://*:5555
interface=tcp://192.168.1.121:5555
;interface=tcp://192.168.1.122:5555

[logs]
; LOG_ERR, LOG_WARN, LOG_INFO, LOG_DEBUG, LOG_OFF
level=LOG_INFO

[bash_script]
file=/opt/rdp-broker/bin/agent.sh
```


3. You have to run **rdp-broker** on dedicated server (`192.168.1.99`) with config file like:

`/opt/rdp-broker/bin/rdp-broker -f /opt/rdp-broker/etc/rdp-broker/rdp-broker.ini -d`

```
[server]
; 192.168.1.99, 127.0.0.1, All
interface=All
port=3389

[logs]
; LOG_ERR, LOG_WARN, LOG_INFO, LOG_DEBUG, LOG_OFF
level=LOG_INFO

[tls]
cert=/opt/rdp-broker/etc/ssl-cert-snakeoil.pem
key=/opt/rdp-broker/etc/ssl-cert-snakeoil.key

[agents]
url-1=tcp://192.168.1.121:5555
url-2=tcp://192.168.1.122:5555
```

**Certificate** and **Key** better take from **xrdp** installation (*/etc/xrdp/cert.pem and /etc/xrdp/key.pem*), but you can generate independent ones.
In the case of independent Certificate *rdp-client* will ask validation more than one time. 

5. Run *rdp-client* like `"xfreerdp3 /cert:ignore ... /v:192.168.1.99"` to skip problem with certifacates validation.
It's Ok for trusted network. 

TODO:

1. ~~broker/agent have to run as daemon~~
2. ~~More strictly check config files~~
3. TLS connection between Broker and Agents
4. ~~Parallel access Broker to Agents~~ Partially finished but further improvement possible.
5. Probably include bash-script logic into Agent. But it's the last step of the project -)
6. Think it over how to start **rdp-broker** и **xrdp** on the same host because they have to share the same port **3389**.
Not sure if it is very important.
