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


test('Account sign', (t) => {
  const acc = new Account()
  acc.generateOneTimeKeys(4)
  t.true(isString(acc.sign('sdasdasdasd')))
})

test('Account sessions', (t) => {
  const alice = new Account();
  const bob = new Account;

  bob.generateOneTimeKeys(1);

  const session = alice.createOutboundSession(bob.curve25519Key, Object.values(bob.oneTimeKeys)[0]);
  const res = session.encrypt('Hello there')
  console.log('res', res, res.ciphertext, res.messageType)
  console.log('decrypt', session.decrypt(res))
  t.pass()
  ///t.true(isString(res))
   //       bob.curve25519_key(),
   //   *bob.one_time_keys().values().next().unwrap(),
//);
})