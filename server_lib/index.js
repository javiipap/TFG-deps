const nativeBinding = require('./server_utilities.linux-x64-gnu.node');
if (!nativeBinding) {
  throw Error("Couldn't load binary lib");
}
const { generateElgamalKeypair, encryptVote, eccEncrypt, eccDecrypt, createRequest, generateRsaKeypair, sign, unblind, verify } = nativeBinding

module.exports.generateElgamalKeypair = generateElgamalKeypair
module.exports.encryptVote = encryptVote
module.exports.eccEncrypt = eccEncrypt
module.exports.eccDecrypt = eccDecrypt
module.exports.createRequest = createRequest
module.exports.generateRsaKeypair = generateRsaKeypair
module.exports.sign = sign
module.exports.unblind = unblind
module.exports.verify = verify
