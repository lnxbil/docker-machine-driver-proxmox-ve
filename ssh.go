package ssh

func (d *Driver) generateKey() string {
	// create and save a new SSH key pair
	d.debug("creating new ssh keypair")
	key, err := d.createSSHKey()
	if err != nil {
		return err
	}
	key = strings.TrimSpace(key)
	return fmt.Sprintf("%s %s-%d", key, d.MachineName, time.Now().Unix())
}

func (d *Driver) createSSHKey() (string, error) {
	sshKeyPath := d.ResolveStorePath("id_rsa")
	if err := mssh.GenerateSSHKey(sshKeyPath); err != nil {
		return "", err
	}
	key, err := ioutil.ReadFile(sshKeyPath + ".pub")
	if err != nil {
		return "", err
	}
	return string(key), nil
}

// GetKeyPair returns a public/private key pair and an optional error
func GetKeyPair(file string) (string, string, error) {
	// read keys from file
	_, err := os.Stat(file)
	if err == nil {
		priv, err := ioutil.ReadFile(file)
		if err != nil {
			fmt.Printf("Failed to read file - %s", err)
			goto genKeys
		}
		pub, err := ioutil.ReadFile(file + ".pub")
		if err != nil {
			fmt.Printf("Failed to read pub file - %s", err)
			goto genKeys
		}
		return string(pub), string(priv), nil
	}

	// generate keys and save to file
genKeys:
	pub, priv, err := GenKeyPair()
	err = ioutil.WriteFile(file, []byte(priv), 0600)
	if err != nil {
		return "", "", fmt.Errorf("Failed to write file - %s", err)
	}
	err = ioutil.WriteFile(file+".pub", []byte(pub), 0644)
	if err != nil {
		return "", "", fmt.Errorf("Failed to write pub file - %s", err)
	}

	return pub, priv, nil
}

// GenKeyPair returns a freshly created public/private key pair and an optional error
func GenKeyPair() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	var private bytes.Buffer
	if err := pem.Encode(&private, privateKeyPEM); err != nil {
		return "", "", err
	}

	// generate public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	public := ssh.MarshalAuthorizedKey(pub)
	return string(public), private.String(), nil
}

func getUUIDFromSmbios1(str string) string {
	var re = regexp.MustCompile(`(?m)uuid=([\d\w-]{1,})[,]{0,1}.*$`)
	return re.FindStringSubmatch(fmt.Sprintf("%s", str))[1]
}
