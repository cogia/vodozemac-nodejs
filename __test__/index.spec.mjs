import test from 'ava'

import {Account} from '../index.js'
import {isObject, isString} from "lodash-es";

test('Account init from native', (t) => {
  const acc = new Account()
  t.pass()
})

test('Account generate keys', (t) => {
  const acc = new Account()
  acc.generateOneTimeKeys(4)
  t.is(Object.keys(acc.oneTimeKeys).length, 4)
  t.true('ed25519' in acc.identityKeys())
})


test('Account pickle keys', (t) => {
  const acc = new Account()
  t.throws(() => acc.pickle('sddd'))
  const pass = '21gCTR9zmeMq6hpH7DlAUeXIMWMBrAUe'
  t.true(isString(acc.pickle(pass)))
  t.true(isObject(Account.fromPickle(acc.pickle(pass), pass)))
})
