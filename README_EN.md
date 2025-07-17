### RDP Broker

Project goal is to combine standalone XRDP servers into one cluster.

*RDP Broker* works in parallel with XRDP. It makes because:
1. not interfere with original XRDP.
2. test *proof-of-concept*.

*RDP Broker* built on top of libraries  *FreeRDP* и *NNG*.

On every host with running **xrdp** you need to run **rdp-agent** with config file like:
```
[server]
; examples: tcp://*:5555, tcp://127.0.0.01:5555 
interface=tcp://192.168.1.121:5555

[logs]
; LOG_NONE, LOG_ERR, LOG_WARN, LOG_NOTICE, LOG_INFO, LOG_DEBUG
level=LOG_NOTICE

[bash_script]
file=/opt/rdp-agent/agent.sh
```

The most interesting in this config is *bash* script "/opt/rdp-agent/agent.sh" which get UserName as input parameter and return information about existence of such a user on server.
Also script return *"RDP LA"* (rdp load average), i.e. information that allow **rdp-broker** to start new rdp session on the least loaded server if User session not exist for now.

**rdp-broker** has to be run on dedicated server with config file like:
```
[server]
; examples: 127.0.0.1, 192.168.1.99
interface=All
port=3389

[logs]
; LOG_NONE, LOG_ERR, LOG_WARN, LOG_NOTICE, LOG_INFO, LOG_DEBUG
level=LOG_NOTICE

[tls]
cert=/opt/freerdp3/etc/proxy.crt
key=/opt/freerdp3/etc/proxy.key

[agents]
url-1=tcp://192.168.1.121:5555
url-2=tcp://192.168.1.122:5555
```

Certificate and Key better take from **xrdp** installation, but you can generate independent ones.
In the case of independent Certificate *rdp-client* will ask validation more than one time. 


TODO:

1. ~~broker/agent have to run as daemon~~
2. ~~More strictly check config files~~
3. TLS connection between Broker and Agents
4. ~~Parallel access Broker to Agents~~ Partially finished but further improvement possible.
5. Probably include bash-script logic into Agent. But it's the last step of the project -)
6. Think it over how to start **rdp-broker** и **xrdp** on the same host because they have to share the same port **3389**.
Not sure if it is very important.
