package main

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"flag"
	"fmt"
	logger "github.com/apcera/gnatsd/logger"
	"github.com/mitchellh/goamz/aws"
	"github.com/mitchellh/goamz/ec2"
	org "github.com/wallyqs/org-go"
	"io/ioutil"
	"time"
)

const ORG_ORCHESTRATE_VERSION = "0.0.1"

var log = logger.NewStdLogger(true, false, true, true, false)

var setupfile = flag.String("f", "", "Setup file in Org mode")

func init() {
	flag.Parse()
}

func filterSrcBlocks(tokens []interface{}) []*org.OrgSrcBlock {
	blocks := make([]*org.OrgSrcBlock, 0)

	for _, t := range tokens {
		switch o := t.(type) {
		case *org.OrgSrcBlock:
			blocks = append(blocks, o)
		}
	}

	return blocks
}

func NewSSHSession(ip string, config *ssh.ClientConfig) *ssh.Session {

	client, err := ssh.Dial("tcp", ip+":22", config)
	if err != nil {
		panic("Failed creating a client: " + err.Error())
	}

	session, err := client.NewSession()
	if err != nil {
		panic("Failed establishing session: " + err.Error())
	}
	return session
}

func main() {
	rawContents, err := ioutil.ReadFile(*setupfile)
	if err != nil {
		log.Fatalf("Problem reading the file: %v \n", err)
	}
	contents := string(rawContents)

	config := org.Preprocess(contents)
	tokens := org.Tokenize(contents, config)
	blocks := filterSrcBlocks(tokens)

	auth := aws.Auth{config.Settings["AWS_ACCESS_KEY"], config.Settings["AWS_SECRET_KEY"], ""}
	ec2conn := ec2.New(auth, aws.Regions[config.Settings["AWS_REGION"]])

	for _, src := range blocks {
		log.Noticef("Launching task: #+%s", src.Name)
		log.Debugf("Headers: %vg", src.Headers)

		securitygroups := make([]ec2.SecurityGroup, 0)
		securitygroups = append(securitygroups, ec2.SecurityGroup{Id: src.Headers[":security_group"]})

		runOpts := &ec2.RunInstances{
			ImageId:                  src.Headers[":ami"],
			InstanceType:             src.Headers[":instance_type"],
			KeyName:                  src.Headers[":key_name"],
			AssociatePublicIpAddress: true,
			SecurityGroups:           securitygroups,
		}

		resp, err := ec2conn.RunInstances(runOpts)
		if err != nil {
			log.Debugf("Response: %v", resp)
			log.Errorf("Error launching source instance: %s", err)
		}
		instId := resp.Instances[0].InstanceId
		log.Noticef("Created instance: %s ", instId)

		log.Noticef("Waiting 5 seconds before getting its state...")
		time.Sleep(time.Second * 5)

		// TODO: Wait for the state of the remote server that was being done
		resp2, err := ec2conn.Instances([]string{instId}, nil)
		if err != nil {
			log.Debugf("Response: %v", resp)
			log.Errorf("Error fetching instance info: %s", err)
		}

		instance := resp2.Reservations[0].Instances[0]
		ip := instance.PublicIpAddress
		log.Noticef("Waiting 60 seconds for node to be ready...")
		time.Sleep(time.Second * 60)

		// TODO: Make it possible to specify key per block
		privateBytes, err := ioutil.ReadFile(config.Settings["SSHIDENTITYFILE"])
		if err != nil {
			panic("Failed to load private key")
		}
		private, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			panic("Failed to parse private key: " + err.Error())
		}
		log.Noticef("%v", src.Headers)
		clientConfig := &ssh.ClientConfig{
			User: src.Headers[":user"],
			Auth: []ssh.AuthMethod{ssh.PublicKeys(private)},
		}

		// Transport the code block file
		//
		log.Noticef("Connecting to instance %s running at %s...", instId, ip)
		scpSession := NewSSHSession(ip, clientConfig)
		defer scpSession.Close()

		go func() {
			w, _ := scpSession.StdinPipe()
			defer w.Close()
			fmt.Fprintln(w, "C0644", len(src.RawContent), "ob-1")
			fmt.Fprint(w, src.RawContent)
			fmt.Fprint(w, "\x00")
		}()

		if err := scpSession.Run("mkdir -p /tmp/ob/ && /usr/bin/scp -qrt /tmp/ob/"); err != nil {
			panic("Failed to run: " + err.Error())
		}

		// TODO: Flush buffered output rather than waiting for command to finish
		remoteCmdSession := NewSSHSession(ip, clientConfig)
		defer remoteCmdSession.Close()

		var b bytes.Buffer
		remoteCmdSession.Stdout = &b

		if err := remoteCmdSession.Run("sh -c 'bash /tmp/ob/ob-1'"); err != nil {
			panic("Failed running remote command")
		}
		log.Noticef("Command finished. Output:")
		fmt.Println(b.String())
	}

}
