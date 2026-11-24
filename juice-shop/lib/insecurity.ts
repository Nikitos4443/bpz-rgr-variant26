/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import { expressjwt } from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */
// eslint-disable-next-line @typescript-eslint/prefer-ts-expect-error
// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9V4a6whCsUKeL
ROd1FwYkYD2T4wPqnbJSOmmKm/Z0UHQxxT+fYHWb1yL+cLbWgxbRA4NAShE5tyhu
zf2l11HbTxliTDmxp8y/juMm13HITcgjaBVlIcyjJ+sDsvqSVlJy4mTrRTH9RrSX
1WvzJ4NjUE5xWFVCI4hhqbrlugpPExmKxlApQWeFO+1QxmQxCUYE0oTsTeBWdc9j
0rVZSyFxd7KVlNTpSqvw0EebvUpzUNKAgqUzN/WkApPiyGmhxnuPQ4urHe0srtO0
uOTDjCKBhmwSOEbfNWT0WUM8l8+W4AJ15Q3Qu75/g9TUHEsccjxvA4ducaTHiaEL
kPY+ZdWVAgMBAAECggEACc7WYlHk24rkBZarUglAHrNDjVJq+gTINMfk1AgciKLq
70cTSCC5huSVN06ZvLFBWyYORE7HPKZMYw0ARiPKEDe1OL56a0WmGV1/+RublRop
CLh+tI8/J/Z3Oej+tNo23s+eawIvGDpzkWfooHRcCHwjoW3HdivGsp8VrjUTDUx4
/5MUFFFTLVM5bPQ4qcXXM3s56xEZC1LDDG3tt6PefyR0lTStg5Hc+dcWc8RiqRio
y+NXMyyCpO4PcKsNUhjfbsmsXxQR2N/lbfMrROFXAmIN2zaIiK7TUpeE3FEaqU1h
UoZTfzMjlQM1kU5XpKLs2isunCZ7zaDAhafGWsqIsQKBgQDi5yAdV6jIa+N0Tqi6
qODu9tuYWtR0VYklZryrHravqpBfM4nTOJ3RXWdkW/wnAJuIvx8fSefR15EVxa/Y
0Melb8dSULEpUFcb7mNpHs16YKM5QLcBGES2wLYTWRiWmEgRYKBdLpFAT42unzzN
ANLWXu9ItTvuHrsE0MdJ+mFD/QKBgQDVn1UilqvmwEhkSFXe3xQR1IiiRMHeZFpX
1DdfQnDkOKyApCTrBhKAVX6O5xx2wD3smNI0MT/qYR8OOkRkPRRJtmH1DTkttq7K
wGtioRd/HU0BB0rSSPFb1iSBBzsUd06ik8SObwQdH/pg76rMXwUziCo0pNeoP3gx
cgCVD1pveQKBgBDcZ/CGQQ6TpdVQuw0T25MmWO8bYMo8SPK0jbSRlbW8EPpiFA3U
GTYjoLk+dKBZVTV2LlPe5BEd2bQqeoS8DvnmMoOVZ3TQeYij0FNRbKd5YuewPWkh
aonCDEWny0H1kvVnnsMN4NFMmBSv1I7PTtuLNnDKtudc9TzIXubKakvpAoGBAKoG
kTpgdh3JOVUoBcDICS9P3BhbZXreoNF7BT96oGPlf9c7zm6JfLxMT9jptcwGosLn
t5b3BApGlvM6CSlHPBiXY0wp5DKwTlrt4Aq2cP8pkRqadUD98azIunFAEhPuCdZ4
il9bmQidZSk2WNklX/xuCjmwYj11lvKz7Ca3+6DxAoGBAKo5BXAuAs5AiUNFGw1d
qq7FYK9AYsvQ08NNYW3r9pLBJQplATlif6k19egOskN8K+Jg4mBM4Bjvg8ZZ/1cx
ASUIo1Pnpki/wCumMBZdJCb4JuIKNIBuPyqFQUV5TpEKxKyNQC/JB7A641ZMtOTa
CW1ZQxtL6Yf6+WzMY4TTz2ah
-----END PRIVATE KEY-----`

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

// express-jwt 8.x: явно фіксуємо алгоритм RS256 (захист від alg:none та HS/RS-плутанини).
export const isAuthorized = () => expressjwt({ secret: publicKey, algorithms: ['RS256'] })
export const denyAll = () => expressjwt({ secret: '' + Math.random(), algorithms: ['HS256'] })
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const verify = (token: string) => {
  // jws 4.x вимагає явного алгоритму; фіксуємо RS256 (захист від alg confusion / alg:none).
  try {
    return token ? (jws.verify as ((token: string, algorithm: string, secret: string) => boolean))(token, 'RS256', publicKey) : false
  } catch {
    return false
  }
}
export const decode = (token: string) => { return jws.decode(token)?.payload }

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }
  const decoded = z85.decode(coupon)
  if (decoded && (hasValidFormat(decoded.toString()) != null)) {
    const parts = decoded.toString().split('-')
    const validity = parts[0]
    if (utils.toMMMYY(new Date()) === validity) {
      const discount = parts[1]
      return parseInt(discount)
    }
  }
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl) // vuln-code-snippet vuln-line redirectChallenge
  }
  return allowed
}
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac('sha256', privateKey)
  return hmac.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

// Middleware, що пропускає лише користувачів з роллю admin (для адмін-ендпоінтів).
export const isAdmin = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.admin) {
      next()
    } else {
      res.status(403).json({ error: 'Requires administrator privileges' })
    }
  }
}

// Перевірка, що кошик/ресурс із заданим basket id належить автентифікованому користувачу.
export const ownsBasket = (req: Request, basketId: string | number) => {
  const user = authenticatedUsers.from(req)
  return !!(user?.bid) && String(user.bid) === String(basketId)
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error: any) {
      res.status(401).json({ status: 'error', message: error })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token) {
    jwt.verify(token, publicKey, (err: Error | null, decoded: any) => {
      if (err === null) {
        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          res.cookie('token', token)
        }
      }
    })
  }
  next()
}
