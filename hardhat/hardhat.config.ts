import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
require('dotenv').config();
require("@nomiclabs/hardhat-ethers");
const { ALCHEMY_URL_GOERLI, PRIVATE_KEY } = process.env;

const config: HardhatUserConfig = {
  solidity: "0.8.17",
  defaultNetwork: "goerli",
   networks: {
      hardhat: {},
      goerli: {
         url: ALCHEMY_URL_GOERLI,
         accounts: [`0x${PRIVATE_KEY}`]
      }
   },
};

export default config;
