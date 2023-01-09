import { useEffect, useState } from "react";
import Web3 from "web3"
import "./App.css";

function App() {
  const [currentAccount, setCurrentAccount] = useState(null);
  const [isVerified, setIsVerified] = useState(false);
  const [jwtToken, setjwtToken] = useState(null);

  const checkWalletIsConnected = async () => {
    const { ethereum } = window;
  
    if (!ethereum) {
      console.log("Make sure you have MetaMask installed!");
      return;
    } else {
      console.log("Wallet exists! We're ready to go!");
    }
  
    const accounts = await ethereum.request({ method: "eth_accounts" });
  
    if (accounts.length !== 0) {
      const account = accounts[0];
      console.log("Found an authorized account: ", account);
      setCurrentAccount(account);
    } else {
      console.log("No authorized account found");
    }
  };

  const connectWalletHandler = async () => {
    const { ethereum } = window;
  
    if (!ethereum) {
      alert("Please install MetaMask!");
    }
  
    try {
      const accounts = await ethereum.request({ method: "eth_requestAccounts" });
      console.log("Found an account! Address: ", accounts[0]);
      setCurrentAccount(accounts[0]);
    } catch (err) {
      console.log(err);
    }
  };

  const signHash = async() => {
    const provider = window.ethereum || window.web3?.provider || null
    if (!provider) {
      console.error('!provider')
      return
    }

    const web3 = new Web3(provider)
    const [tgt_addr] = await web3.eth.requestAccounts()

    const api_url = 'https://1vlevj4eak.execute-api.ap-northeast-1.amazonaws.com/demo/wallet-connect'
    const message = 'Please Sign This Request for Accsessing to Service'
    const password = ''
    const signature = await web3.eth.personal.sign(message, tgt_addr, password)
    console.log(signature);
    
    const response = await fetch(api_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=UTF-8',
      },
      body: JSON.stringify({
        message, tgt_addr, signature
      }),
    })
    console.log(response)
    const body = await response.json()
    if(body.status=='success') {
      setIsVerified(true);
      setjwtToken(body.token)
    }
  };

  const connectWalletButton = () => {
    return (
      <button
        onClick={connectWalletHandler}
        className="cta-button connect-wallet-button"
      >
        Connect Wallet
      </button>
    );
  };

  const signPrivateKey = () => {
    return (
      <button onClick={signHash} className="cta-button mint-nft-button">
        Digital Signature
      </button>
    );
  };

  useEffect(() => {
    checkWalletIsConnected();
  }, []);

  return (
    <div className="main-app">
      <h1>Scrappy Squirrels Tutorial</h1>
      <div>{currentAccount ? signPrivateKey() : connectWalletButton()}</div>
      <div>
        <h2>{isVerified ? jwtToken : 'You have not connect wallet yet'}</h2>
        </div>
    </div>
  );
}

export default App;