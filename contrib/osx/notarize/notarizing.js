
require('dotenv').config()
const { notarize } = require('electron-notarize')

const notarizing = (path) => {
  return notarize({
    appBundleId: 'org.verge.electrum',
    appPath: path,
    appleId: process.env.APPLE_ID,
    appleIdPassword: process.env.APPLE_ID_PASS,
    ascProvider: process.env.APPLE_ASC_PROVIDER
  })
}

const [_, _1, path] = process.argv
console.log("Processing", path)
return notarizing(path)
  .then((e) => {
    console.log(e)
    process.exit(0)
  }).catch((e) => {
    console.log(e)
    process.exit(-1)
  })