import configProd from './prod.js'
import configDev from './dev.js'

interface Config {
  tokenKey: string | undefined;
}

export const config : Config = (process.env.NODE_ENV === 'production')
? configProd
: configDev

// config = configProd
// if (process.env.NODE_ENV === 'production') { //false && 
//   config = configProd
// } else {
//   config = configDev
// }
// config.isGuestMode = true