import { ethers } from "hardhat";

async function main() {
  const currentTimestampInSeconds = Math.round(Date.now() / 1000);


  const NftLogic = await ethers.getContractFactory("NftLogic");
  const contract = await NftLogic.deploy();

  await contract.deployed();

  console.log(`NftLogic  deployed to ${contract.address}`);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
