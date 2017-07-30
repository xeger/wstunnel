ssh -L 23000:localhost:32813 -L 8500:localhost:8500 ec2-54-210-165-4.compute-1.amazonaws.com

go build .; and ./wstunnel srv -port 8080 -cors .rightscale.com -acl-url http://localhost:23000 -cookie rs_gbl

./wstunnel cli -tunnel ws://localhost:8080 -token hackeveryday2017q3 -server https://news.google.com
