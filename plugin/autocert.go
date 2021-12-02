/**

    "Modlishka" Reverse Proxy.

    Copyright 2018 (C) Piotr Duszyński piotr[at]duszynski.eu. All rights reserved.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    You should have received a copy of the Modlishka License along with this program.

**/

package plugin

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/drk1wi/Modlishka/config"
	"github.com/drk1wi/Modlishka/log"
)

// Paste your CA certificate and key in the following format
// Ref: https://github.com/drk1wi/Modlishka/wiki/Quickstart-tutorial

const CA_CERT = `-----BEGIN CERTIFICATE-----
MIID1TCCAr2gAwIBAgIUVFMg78eh8viNLZx8u382wtoUJ+4wDQYJKoZIhvcNAQEL
BQAwejELMAkGA1UEBhMCdXMxCzAJBgNVBAgMAm55MQswCQYDVQQHDAJueTERMA8G
A1UECgwIRmFjZWxvb2sxDjAMBgNVBAsMBUxvZ0luMRAwDgYDVQQDDAdMaW51eElu
MRwwGgYJKoZIhvcNAQkBFg10ZXN0QHRlc3QuY29tMB4XDTIxMTIwMjAyMDgyNFoX
DTI0MDkyMTAyMDgyNFowejELMAkGA1UEBhMCdXMxCzAJBgNVBAgMAm55MQswCQYD
VQQHDAJueTERMA8GA1UECgwIRmFjZWxvb2sxDjAMBgNVBAsMBUxvZ0luMRAwDgYD
VQQDDAdMaW51eEluMRwwGgYJKoZIhvcNAQkBFg10ZXN0QHRlc3QuY29tMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvikQhYjq96yQt35YohFGO1Lfc7Sg
HGJPWPwh+FFWu2RQcMuFSjT+2XfM1Z9wjBvDti1D1EFJf6kmLfNqULz8UZhPvby7
DfqHovvZbTzwzPpC+3QSd0mMrtrMvX2VgJP7CZo+jmt86ZNnubxRzUbzI/3RzFFK
UFGXEnVuEEl4/OyE5R0pzxEdq9iJlKtYhGmYEhTNPVBR05NygoE8l1WsUt6WWb+A
NlQ75igvJOZOG/1ei9mNG/5Ilt4sFQfDsL8NQxm6tBhLRs4mAFlXcrR5p7UxOP7o
OvbU2oh00xM2tfZbEoqUAj9GO0idj99jhvDhT4Aace7sbnw20dgWtE5YqQIDAQAB
o1MwUTAdBgNVHQ4EFgQU1DHWtmI1FAT/II/ZIHcqUv2uWuYwHwYDVR0jBBgwFoAU
1DHWtmI1FAT/II/ZIHcqUv2uWuYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAmhhQ3NouetWEvbIOmEHP/p3bUxLF5JmpvazX4SpOJ1CJl5Sn63hJ
yVPbyYkfOlq1EMM0EymtGzZ0hPiioZb09gg1jKqjx379rTLIjWZyK68nnY74V1h0
K5chLyh5IB7rs4KR26Q1ItA52cLdH1vmolgTCwiuWPR0O6QYojRs8/2R9kpiaZGR
b8xH/MpEyJugP5oViGzx61otV6fR05Z1cyidmqPpmipUflPC0b1J+QBPx+rM53jk
k6XI1/5jfXhnuztOrqscs5rx6YEnZzqDERcGo6p3ro6XvYVpnOt6UHmZ5eQmoMSU
AasKZUYZuCjhXIUedbcLxKkSS8afkYT5MA==
-----END CERTIFICATE-----`

const CA_CERT_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvikQhYjq96yQt35YohFGO1Lfc7SgHGJPWPwh+FFWu2RQcMuF
SjT+2XfM1Z9wjBvDti1D1EFJf6kmLfNqULz8UZhPvby7DfqHovvZbTzwzPpC+3QS
d0mMrtrMvX2VgJP7CZo+jmt86ZNnubxRzUbzI/3RzFFKUFGXEnVuEEl4/OyE5R0p
zxEdq9iJlKtYhGmYEhTNPVBR05NygoE8l1WsUt6WWb+ANlQ75igvJOZOG/1ei9mN
G/5Ilt4sFQfDsL8NQxm6tBhLRs4mAFlXcrR5p7UxOP7oOvbU2oh00xM2tfZbEoqU
Aj9GO0idj99jhvDhT4Aace7sbnw20dgWtE5YqQIDAQABAoIBAHKWxEHzk8PT1RD9
reNbjXrKIaTTv3fbNf1lUgMU4LLjbCXMPnHNJZVeP6yq+2Myh+kLtcf935ByGXOv
Lu2gNFvm8IZhaEawJXPtV8Qf6OtcE2j7NPV0+LWVW7MELkbg5XGP5Qplc0w9a0/d
T13n1zRlCzuX8LQdtm+FG+HspF+kCx7ZZ2x6649VVkRb9KaQ0S7qB38W89o1/OtK
n3PRRjh3iviqvMEWPRtkYP8Koftxpa+IWUwXLhp3ABxlfirXKAHPXr4wBi9mxKWG
nG9H46hmwckGcHj2btTDhxOpy/C7MTff3jskYvEUTHNNNv+30z0i/5P3JsZgKadb
bY3SyUECgYEA+iI47apkJ2d3f6YiH9RUgtGlxJ3c8ng3yh3LnNfUUZ0tuT+5Wkws
F4G0JMNfa2PU0+uvbsPlBOtKhVZyiVMQuRlMRo3jBeiOEwVYk6bdr9TKdMRVZZOz
V1aO2g8FyQtz2nUP9lPq9ZAv0jSpBxvdW76Pk2h8UoWFef/BXWF0AoUCgYEAwp7E
xJjS3s/6AuTZmIGU4+JQwjENwy1Y937SwDIbrB3Pv8Y1nY25se4M6s2GXEMxlWDv
ifKpAI31VhUSmwCWEQAI1AaVE8uJPw7yivkOwC0ioCRveIt5effqYpUQGgcVP+bT
b6MPH0oZqoGnmvQla3L6CfXuXrQZ0do5Otu7QNUCgYEApzlV4d42UvmjNF23Fpx3
W3YZYtc/LYMdmSxOQa8xLNbuCJkHq8yc9aIq8yECm+MEGCHLCTxB0gYTrgzbSd+U
oIq/KbQWAI823JSIYT3/m1uhdmsDxIL4NP2TR0kfzwavD2+PmlkEDeO1dMzr6+q/
FGTTy/LgmrLVR3iqp2lNi5kCgYAWUFHLIKJ8vWey0T5JiAHkJtyPh0RGrnpW1gmf
057smvZozHb1O3yg8+QzP6E6DtIuiFCuhk3uLFiGqB/b+bM6+8AHX0HUZS+1NSeF
24xfaE1iAwtszMD+xPfwmZqhAVLkYri3QgDH250ZuYfX8kogCay1W6ca4JddQiHx
p6POiQKBgBNFTaziDuyDXcLoy5+agEFKUHBoXxbpw1K6YAiwxGeP0kgfQNzixlnY
O6keVQ92nlm5DSTgr3rRJ6I/eWWT3MkMAXRTinVaPFCVyFlLdqkShQAqFRSaaPkH
GvKyTBONh1FnmsFhkB2ad7nqpRhLMTrVohuGwfm9nuM+NjWjwQ7M
-----END RSA PRIVATE KEY-----`

func init() {

	s := Property{}

	s.Name = "autocert"
	s.Version = "0.1"
	s.Description = "This plugin is used to auto generate certificate for you . Really useful for testing different configuration flags against your targets. "

	s.Flags = func() {

		if *config.C.ForceHTTP == false {
			if len(*config.C.TLSCertificate) == 0 && len(*config.C.TLSKey) == 0 {

				log.Infof("Autocert plugin: Auto-generating %s domain TLS certificate",*config.C.ProxyDomain)

				CAcert := CA_CERT
				CAkey := CA_CERT_KEY

				catls, err := tls.X509KeyPair([]byte(CAcert), []byte(CAkey))
				if err != nil {
					panic(err)
				}
				ca, err := x509.ParseCertificate(catls.Certificate[0])
				if err != nil {
					panic(err)
				}

				var n int32
				binary.Read(rand.Reader, binary.LittleEndian, &n)

				template := &x509.Certificate{
					IsCA:                  false,
					BasicConstraintsValid: true,
					SubjectKeyId:          []byte{1, 2, 3},
					SerialNumber:          big.NewInt(int64(n)),
					DNSNames:              []string{*config.C.ProxyDomain, "*." + *config.C.ProxyDomain},
					Subject: pkix.Name{
						Country:      []string{"Earth"},
						Organization: []string{"Mother Nature"},
						CommonName:   *config.C.ProxyDomain,
					},
					NotBefore: time.Now(),
					NotAfter:  time.Now().AddDate(5, 5, 5),
				}

				// generate private key
				privatekey, err := rsa.GenerateKey(rand.Reader, 2048)

				if err != nil {
					log.Errorf("Error generating key: %s", err)
				}
				var privateKey = &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(privatekey),
				}

				//dump
				buf := new(bytes.Buffer)
				pem.Encode(buf, privateKey)
				tlskeyStr := buf.String()
				config.C.TLSKey = &tlskeyStr
				log.Debugf("AutoCert plugin generated TlsKey:\n %s", *config.C.TLSKey)

				// generate self signed cert
				publickey := &privatekey.PublicKey

				// create a self-signed certificate. template = parent
				//var parent = template
				var parent = ca

				cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey, catls.PrivateKey)

				buf = new(bytes.Buffer)
				pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert})

				tlscertStr := buf.String()
				config.C.TLSCertificate = &tlscertStr
				log.Debugf("AutoCert plugin generated TlsCert:\n %s", *config.C.TLSCertificate)

				//the cert is auto-generated anyway
				*config.C.TLSPool = ""

				if err != nil {
					log.Errorf("Error creating certificate: %s", err)
				}

			}
		}

	}

	// Register all the function hooks
	s.Register()
}
