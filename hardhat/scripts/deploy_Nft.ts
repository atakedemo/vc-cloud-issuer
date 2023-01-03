import { ethers } from "hardhat";

async function main() {
  const Nft = await ethers.getContractFactory("Bamb00NFT");
  const contract = await Nft.deploy("0x4BBD2Bb013A558BADd9eE6A714990F9cF9cA6AcD");

  await contract.deployed();

  console.log(`Nft  deployed to ${contract.address}`);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
