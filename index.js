const express = require('express')
const cors = require('cors')
const morgan = require('morgan')
const helmet = require('helmet')
const fs = require('fs');
const http = require('http');
const https = require('https');
const axios = require('axios');
const { promisify } = require('util')
const home = require('os').homedir()
import crypto from "crypto";
const { exec } = require('child_process');

const { WEBHOOK_SECRET } = process.env;

const privateKey  = fs.readFileSync(`${home}/msft-verification-cloudflare-certs/private.key`, 'utf8');
const certificate = fs.readFileSync(`${home}/msft-verification-cloudflare-certs/origin.pem`, 'utf8');
const msaSecret = fs.readFileSync(`${home}/msft-verification-cloudflare-certs/msasecret.txt`, 'utf8');

var credentials = {key: privateKey, cert: certificate};

const app = express()

app.use(helmet())
app.use(morgan('tiny'))
app.use(cors())
app.use(express.json())

app.get('/authorize', (req, res) => {
  const { code, error, error_description } = req.query;

  if (error) {
    res.redirect(`/error_generic.html#${error_description}`)
    return
  }

  // Get full token from the provided code
  axios(
    {
      url: 'https://login.live.com/oauth20_token.srf',
      data: `client_id=bb54a446-5296-47ac-a77a-a3152808eaa9&client_secret=${msaSecret}&code=${code}&grant_type=authorization_code&redirect_uri=https://identity-platform.cavecraft.net:2053/authorize`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    }
  )
    .then((result) => {

      // Now, we need to talk to Xbox Live
      axios({
        url: 'https://user.auth.xboxlive.com/user/authenticate',
        data: JSON.stringify({
          'Properties': {
            'AuthMethod': 'RPS',
            'SiteName': 'user.auth.xboxlive.com',
            'RpsTicket': `d=${result.data.access_token}`,
          },
          'RelyingParty': 'http://auth.xboxlive.com',
          'TokenType': 'JWT',
        }),
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
      })
        .then((result) => {
          // (save this for later)
          const userHash = result.data.DisplayClaims.xui[0].uhs

          // Now we need to get our XSTS Token
          axios({
            url: 'https://xsts.auth.xboxlive.com/xsts/authorize',
            data: JSON.stringify({
              'Properties': {
                'SandboxId': 'RETAIL',
                'UserTokens': [
                  result.data.Token
                ],
              },
              'RelyingParty': 'rp://api.minecraftservices.com/',
              'TokenType': 'JWT',
            }),
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
            },
          })
            .then((result) => {
              // Finally, we actually auth w/Minecraft!!!!

              axios({
                url: 'https://api.minecraftservices.com/authentication/login_with_xbox',
                data: JSON.stringify({
                  'identityToken': `XBL3.0 x=${userHash};${result.data.Token}`
                }),
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Accept': 'application/json',
                },
              })
                .then((result) => {
                  axios({
                    url: 'https://api.minecraftservices.com/minecraft/profile',
                    method: 'GET',
                    headers: {
                      'Authorization': `Bearer ${result.data.access_token}`,
                    },
                  })
                    .then((result) => {
                      // YESSS FINALLY OMG THIS WAS SO HARD

                      const uuid = result.data.id.replace(/[^0-9A-Za-z]/gi, '')

                      fs.appendFile(`${home}/msft-verified-users.txt`, `,${uuid}`, (err) => {
                        if (err) {
                          res.redirect(`/error_generic.html#${err.message}`)
                        } else {
                          res.redirect('/success.html')
                        }
                      })
                    })
                    .catch((error) => {
                      console.log(error)
                      res.redirect(`/error_generic.html#${error.message}`)
                      return;
                    })
                })
                .catch((error) => {
                  console.log(error)
                  res.redirect(`/error_generic.html#${error.message}`)
                  return;
                })
            })
            .catch((error) => {
              switch (error?.response?.data?.XErr) {
                case '2148916233':
                  res.redirect(`/error_migrate.html#${error.message}`)
                  return;
                case '2148916235':
                  res.redirect(`/error_banned.html#${error.message}`)
                  return;
                case '2148916238':
                  res.redirect(`/error_child.html#${error.message}`)
                  return;
                default:
                  console.log(error)
                  res.redirect(`/error_generic.html#${error.message}`)
                  return;
              }
            })
        })
        .catch((error) => {
          console.log(error)
          res.redirect(`/error_generic.html#${error.message}`)
          return;
        })
    })
    .catch((error) => {
      // If the code expired, just get a new one.
      if (error.response.data.error == 'invalid_grant') {
        res.redirect('https://login.live.com/oauth20_authorize.srf?client_id=bb54a446-5296-47ac-a77a-a3152808eaa9&secret_id=b07c8374-aff9-406a-900d-70f6368f8be8&response_type=code&redirect_uri=https://identity-platform.cavecraft.net:2053/authorize&scope=XboxLive.signin%20offline_access&prompt=select_account')
      } else {
        console.log(error)
        res.redirect(`/error_generic.html#${error.message}`)
        return;
      }
    })
})

app.get('/verify/:uuid', (req, res) => {
  const uuid = req.params.uuid.replace(/[^0-9A-Za-z]/gi, '')

  fs.readFile(`${home}/msft-verified-users.txt`, (err, data) => {
    if (err) {
      res.json({error: err.message})
    } else {
      res.json({verified: data.toString().replaceAll(' ', '').split(',').includes(uuid)})
    }
  })
})

app.post('/pushhook', (req, res) => {
  const expectedSignature = "sha1=" +
        crypto.createHmac("sha1", WEBHOOK_SECRET)
            .update(JSON.stringify(request.body))
            .digest("hex");

  // compare the signature against the one in the request
  const signature = request.headers["x-hub-signature"];
  if (signature !== expectedSignature) {
      throw new Error("Invalid signature.");
  } else {
    exec('/var/srvupdater/update.sh')
  }
})

app.use(express.static('./static'))

var httpsServer = https.createServer(credentials, app);
httpsServer.listen(2053, () => {console.log('Started & bound @ port 2053')});
