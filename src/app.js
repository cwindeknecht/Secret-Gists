require('dotenv').config();
const bodyParser = require('body-parser');
const express = require('express');
const octokit = require('@octokit/rest');
const nacl = require('tweetnacl');
nacl.util = require('tweetnacl-util');

// const username = process.env.GITHUB_USER;
// const token = process.env.GITHUB_TOKEN;
// let login = true;
let username;
let token;
let login = false;
const github = octokit({ debug: true });
const server = express();

// Create application/x-www-form-urlencoded parser
const urlencodedParser = bodyParser.urlencoded({ extended: false });

// Generate an access token: https://github.com/settings/tokens
// Set it to be able to create gists
// github.authenticate({
//   type: 'oauth',
//   token,
// });

server.get('/home', (req, res) => {
  // Return a response that documents the other routes/operations available
  if (login) {
    res.send(`
    <html>
      <header><title>Secret Gists! Welcome ${username}</title></header>
      <body>
        <h4>Not ${username}? <a href='/'>Click Here</a>
        <h1>Secret Gists!</h1>
        <h2>Supported operations:</h2>
        <ul>
          <li><i><a href="/gists">GET /gists</a></i>: retrieve a list of gists for the authorized user (including private gists)</li>
          <li><i><a href="/key">GET /key</a></i>: return the secret key used for encryption of secret gists</li>
          <li><i><a href="/secretgist/:id">GET /secretgist/ID</i>: retrieve and decrypt a given secret gist
          <li><i>POST /create { name, content }</i>: create a private gist for the authorized user with given name/content</li>
          <li><i>POST /createsecret { name, content }</i>: create a private and encrypted gist for the authorized user with given name/content</li>
          <li><i><a href="/keyPairGen">Generate Keypair</a></i>: Generate a keypair.  Share your public key for other users of this app to leave encrypted gists that only you can decode with your secret key.</li>
        </ul>
        <h3>Create an *unencrypted* gist</h3>
        <form action="/create" method="post">
          Name: <input type="text" name="name"><br>
          Content:<br><textarea name="content" cols="80" rows="10"></textarea><br>
          <input type="submit" value="Submit">
        </form>
        <h3>Create an *encrypted* gist</h3>
        <form action="/createsecret" method="post">
          Name: <input type="text" name="name"><br>
          Content:<br><textarea name="content" cols="80" rows="10"></textarea><br>
          <input type="submit" value="Submit">
        </form>
        <h3>Create an *encrypted* gist for a friend to decode</h3>
        <form action="/postmessageforfriend" method="post">
          Name: <input type="text" name="name"><br>
          Friend's Public Key: <input type="text" name="publicKey"><br>
          Content:<br><textarea name="content" cols="80" rows="10"></textarea><br>
          <input type="submit" value="Submit">
        </form>
        <h3>Retrieve an *encrypted* gist a friend has posted</h3>
        <form action="/fetchmessagefromfriend" method="get">
          String From Friend: <input type="text" name="messageString"><br>
          <input type="submit" value="Submit">
        </form>
      </body>
    </html>
  `);
  } else {
    res.json({ message: 'Must login first.' });
  }
});

server.get('/gists', (req, res) => {
  if (login) {
    // Retrieve a list of all gists for the currently authorizeded user
    github.gists
      .getForUser({ username })
      .then((response) => {
        res.send(`
          <html>
            <header><title>Secret Gists!</title></header>
            <body>
            <h3> For the official gists of ${username} </h3>
            <a href='https://gist.github.com/${username}'>Click Here</a>
            </body>
          </html>`);
      })
      .catch((err) => {
        res.json(err);
      });
  } else {
    res.json({ message: 'Must login first.' });
  }
});

server.get('/key', (req, res) => {
  if (login) {
    // Return the secret key used for encryption of secret gists
    const savedKey = process.env.SECRET_KEY;
    // Must create saved key first
    if (savedKey) {
      res.json({
        message:
          'Here is your secret key/nonce. You will need it to decode messages. Protect it like a passphrase!',
        SecretKey: savedKey,
      });
    } else {
      res.json({ message: 'You must create a keypair before using this feature' });
    }
  } else {
    res.json({ message: 'Must login first.' });
  }
});

server.get('/secretgist/:id', (req, res) => {
  if (login) {
    // Retrieve and decrypt the secret gist corresponding to the given ID
    const { id } = req.params;
    github.gists
      .get({ id })
      .then((response) => {
        const file = response.data.files;
        const filename = Object.keys(file)[0];
        const content = file[filename].content;
        const nonce = nacl.util.decodeBase64(content.slice(0, 32));
        const box = nacl.util.decodeBase64(content.slice(32));
        const key = nacl.util.decodeBase64(process.env.PUBLIC_KEY);
        const message = nacl.util.encodeUTF8(nacl.secretbox.open(box, nonce, key));
        res.json(message);
      })
      .catch((err) => {
        res.json({ message: 'You must create a keypair before using this feature', err });
      });
  } else {
    res.json({ message: 'Must login first.' });
  }
});

server.get('/keyPairGen', (req, res) => {
  if (login) {
    const keypair = nacl.box.keyPair();
    process.env.SECRET_KEY = nacl.util.encodeBase64(keypair.secretKey);
    process.env.PUBLIC_KEY = nacl.util.encodeBase64(keypair.publicKey);
    // Display the keys as strings
    res.send(`
    <html>
      <header><title>Keypair</title></header>
      <body>
        <h1>Keypair</h1>
        <div>Share your public key with anyone you want to be able to leave you secret messages.</div>
        <div>Keep your secret key safe.  You will need it to decode messages.  Protect it like a passphrase!</div>
        <br/>
        <div>Public Key: ${nacl.util.encodeBase64(keypair.publicKey)}</div>
        <div>Secret Key: ${nacl.util.encodeBase64(keypair.secretKey)}</div>
      </body>
    `);
  } else {
    res.json({ message: 'Must login first.' });
  }
});

server.post('/create', urlencodedParser, (req, res) => {
  if (login) {
    // Create a private gist with name and content given in post request
    const { name, content } = req.body;
    const files = { [name]: { content } };
    github.gists
      .create({ files, public: false })
      .then((response) => {
        res.json({ message: 'Your gist has been created', name, content });
      })
      .catch((err) => {
        res.json(err);
      });
  } else {
    res.json({ message: 'Must login first.' });
  }
});

server.post('/createsecret', urlencodedParser, (req, res) => {
  if (login) {
    // TODO Create a private and encrypted gist with given name/content
    // NOTE - we're only encrypting the content, not the filename
    // To save, we need to keep both encrypted content and nonce
    const { name } = req.body;
    const content = nacl.util.decodeUTF8(req.body.content);
    const nonce = nacl.randomBytes(24);
    const key = nacl.util.decodeBase64(process.env.PUBLIC_KEY);
    const encrypt = nacl.secretbox(content, nonce, key);
    const encryptedContent = nacl.util.encodeBase64(nonce) + nacl.util.encodeBase64(encrypt);
    const files = { [name]: { content: encryptedContent } };
    github.gists
      .create({ files, public: false })
      .then((response) => {
        res.json({ message: 'Your decrypted gist has been created.', name, encryptedContent });
      })
      .catch((err) => {
        res.json(err);
      });
  } else {
    res.json({ message: 'Must login first.' });
  }
});

server.post('/postmessageforfriend', urlencodedParser, (req, res) => {
  if (login) {
    // Create a private and encrypted gist with given name/content
    // using someone else's public key that can be accessed and
    // viewed only by the person with the matching private key
    const savedKey = process.env.SECRET_KEY;
    if (savedKey) {
      // If the key exists, create an asymetrically encrypted message
      // Using their public key
      const { name, publicKey } = req.body;
      const content = nacl.util.decodeUTF8(req.body.content);
      const nonce = nacl.randomBytes(24);
      const key = nacl.util.decodeBase64(process.env.SECRET_KEY);
      const encrypt = nacl.box(content, nonce, nacl.util.decodeBase64(publicKey), key);
      const encryptedContent = nacl.util.encodeBase64(nonce) + nacl.util.encodeBase64(encrypt);
      const files = { [name]: { content: encryptedContent } };
      github.gists
        .create({ files, public: true })
        .then((response) => {
          // Build string that is the messager's public key + encrypted message blob
          // to share with the friend.
          const messageString = `${process.env.PUBLIC_KEY}${encryptedContent}`;
          // Display the string built above
          res.json({ message: `Your encryped message\n${messageString}` });
        })
        .catch((err) => {
          res.json(err);
        });
    } else {
      res.json({ message: 'Error posting message for a friend, generate a key pair first.' });
    }
  } else {
    res.json({ message: 'Must login first.' });
  }
});

server.get('/fetchmessagefromfriend', urlencodedParser, (req, res) => {
  if (login) {
    // Retrieve, decrypt, and display the secret gist corresponding to the given ID
    const { messageString } = req.query;
    const theirKey = nacl.util.decodeBase64(messageString.slice(0, 44));
    const nonce = nacl.util.decodeBase64(messageString.slice(44, 76));
    const box = nacl.util.decodeBase64(messageString.slice(76));
    const secret = nacl.util.decodeBase64(process.env.SECRET_KEY);

    const message = nacl.util.encodeUTF8(nacl.box.open(box, nonce, theirKey, secret));
    res.json(message);
  } else {
    res.json({ message: 'Must login first.' });
  }
});

server.get('/', (req, res) => {
  res.send(`
    <html>
      <header><title>Secret Gists!</title></header>
      <body>
        <h3>Login to Github</h3>
        <form action="/login" method="post">
        Username <input type="text" name="username"><br>
        oauth Token: <input type="text" name="token"><br>
        <input type="submit" value="Submit">
      </form>
      </body>
    </html>
  `);
});
server.post('/login', urlencodedParser, (req, res) => {
  token = req.body.token;
  // log in to GitHub, return success/failure response
  github.authenticate({
    type: 'oauth',
    token,
  });
  setTimeout(() => {
    username = req.body.username;
    login = true;
    res.send(
      `
      <html>
        <header><title>Secret Gists!</title></header>
        <body>
          <h3>Login to Github Successful</h3>
          <a href='/home'>Click Here to contintue to gists</a>
        </body>
      </html>
      `
    );
  }, 3000);
});

/*
Still want to write code? Some possibilities:
-Pretty templates! More forms!
-Better management of gist IDs, use/display other gist fields
-Support editing/deleting existing gists
-Switch from symmetric to asymmetric crypto
-Exchange keys, encrypt messages for each other, share them
-Let the user pass in their private key via POST
*/

server.listen(3000);
