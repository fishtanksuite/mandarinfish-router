var express = require('express');
var bodyParser = require('body-parser');
var isIp = require('is-ip');
var shelljs = require('shelljs');

var ip = require('ip');
var iptables = require('netfilter').iptables;

var app = express();
var iptableEntries = [];

var cidrSubnetWhiteList = [
  //Add IP Subnet to Whitelist
]

app.use(bodyParser.json());
// Delete iptables before restart
// iptables -t nat -F

app.post('/v1/redirect', function(req, res) {

  //Check IP Addresses
  console.log("Validating IP Addresses");
  if(!validateIpv4(req.body.originalIp) || !validateIpv4(req.body.redirectIp)) {
    res.status(400).send({'error': 'Malformed syntax'});
    return;
  }

  //Check ports
  console.log("Validating Ports")

  if(!validatePortNum(req.body.originalPort) || !validatePortNum(req.body.redirectPort)) {
    res.status(400).send({'error': 'Malformed syntax'});
    return;
  }

  console.log("All Port OK");

  //Check if redirect IP is whitelisted
  console.log("Checking if redirect IP is whitelisted");
  if(!checkCidrSubnetWhiteList(req.body.redirectIp, cidrSubnetWhiteList)) {
    res.status(400).send();
    return;
  }

  //Check if iptable already exists
  console.log("Check if iptable already exists");

  exists(req.body.originalIp, req.body.originalPort,
  function() {
    //set iptable
    console.log("iptable doesnt exist");
    var success = setIptable(req.body.originalIp, req.body.redirectIp, req.body.originalPort, req.body.redirectPort);
    if(success) {
      saveIptables();
    }
  },
  function() {
    console.log("iptable exists");
  });


  res.send();

});


app.post('/v0/redirect', function(req, res) {
  if(isIp(req.body.original) && isIp(req.body.redirect)) {
    if(iptableEntries.indexOf(req.body.original) >= 0) {
      console.log('Route from ' + req.body.original + ' to ' + req.body.redirect + ' already set');
      res.status(202).send();
    } else {
      var cmd = "sudo iptables -t nat -A OUTPUT --destination " + req.body.original + " -j DNAT --to-destination " + req.body.redirect;
      if(shelljs.exec(cmd).code !== 0) {
        res.status(500).send({error: 'iptables error'});
      } else {
        console.log('Added redirect from ' + req.body.original + ' to ' + req.body.redirect);
        iptableEntries.push(req.body.original);
        res.send();
      }
    }
  } else {
    res.status(400).send({error: 'Malformed syntax'});
  }
});

app.listen(3000, function() {
  console.log('Mandarinfish Router listening on port 3000');
});

function validatePortNum(_port) {
  //Check if port is a int
  var port = parseInt(_port);
  if(isNaN(port)) {
    console.log("Port: " + port + "is not a number")
    return false;
  }

  //Check if port is in range
  if(port < 0 || port > 65535) {
    console.log("Port: " + port + "is not in range");
    return false;
  }


  return true;
}

function validateIpv4(ipAddress) {
  var isIpv4 = ip.isV4Format(ipAddress);
  console.log("IP: " + ipAddress + " is " + (isIpv4 ? "v4" : "not v4"));
  return isIpv4;
}

function checkCidrSubnetWhiteList(ipAddress, cidrSubnetWhiteList) {
  for(cidrSubnet of cidrSubnetWhiteList) {
    if(ip.cidrSubnet(cidrSubnet).contains(ipAddress)) {
      console.log("IP: " + ipAddress + "is in subnet: " + cidrSubnet);
      if(isHostAddress(ipAddress, cidrSubnet)) {
        console.log("is Host Adress");
        return true;
      } else {
        console.log("is not Host Adress");
      }

    } else {
      console.log("IP: " + ipAddress + "is not in subnet: " + cidrSubnet);
    }
  }
  console.log("IP: " + ipAddress + " is not whitelisted");
  return false;
}

function isHostAddress(ipAddress, cidrSubnet) {
  var infos = ip.cidrSubnet(cidrSubnet);
  return (ipAddress !== infos.networkAddress && ipAddress !== infos.broadcastAddress)
}


function getIptableDump(success, error) {
  iptables.dump({
    table: 'nat',
    chain: 'OUTPUT'
  }, function(error, dump) {
    if(!error) {
      success(dump);
    } else {
      error(error);
    }
  });
}

function exists(dstIpAddress, dPort, success, error) {
  getIptableDump(function(dump) {
    if(!checkIfIptableExists(dstIpAddress, dPort, dump)) {
      success();
    } else {
      error();
    }
  }, function(error) {
    console.log(error);
  });
}

function checkIfIptableExists(dstIpAddress, dPort, dump) {
  var rules = dump['nat'].chains['OUTPUT'].rules;
  for(var rule of rules) {

    var dest = rule.destination.substring(0, rule.destination.length-3);

    console.log(dest +  " == " + dstIpAddress);
    if(dest === dstIpAddress) {
        console.log("port: " + rule.matches.tcp['destination-port'] + " == " + dPort);
        if(rule.matches.tcp['destination-port'] == dPort) {
          console.log("rule with port " + rule.matches.tcp['destination-port'] + " exists");
          return true;
        }
    }
  }
  return false;

}

function iptableExistsForDstAndPort(dstIpAddress, dPort, success, error) {
  iptables.dump({
    table: 'nat'
  }, function(error, dump) {
    if(!error) {
      var rules = dump['nat'].chains['OUTPUT'].rules;
      for(var rule of rules) {
        var dest = rule.destination.substring(0, rule.destination.length-3);
        console.log(dest + ", " + dstIpAddress);
        if(dest === dstIpAddress && dport === rule.matches["destination-port"])
          success(true);
          return;
      }
      success(false);
    } else {
      error(error);
    }

  });
}

function setIptable(originalDst, fakeDst, originalPort, fakePort) {
  var cmd = "sudo iptables -t nat -A OUTPUT -p tcp --destination " + originalDst + " --dport " + originalPort + " -j DNAT --to-destination " + fakeDst + ":" + fakePort;
  return shelljs.exec(cmd).code === 0;

}

function saveIptables() {
  var cmd = "sudo iptables-save > /etc/iptables/rules.v4";
  shelljs.exec(cmd);
}
