import test from 'ava'

import {Account, SessionConfig} from '../index.js'
import {isEqual, isObject, isString} from "lodash-es";
import {equal} from "node:assert";

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
  acc.generateOneTimeKeys(50)
  t.throws(() => acc.pickle('sddd'))
  const pass = '21gCTR9zmeMq6hpH7DlAUeXIMWMBrAUe'
  t.true(isString(acc.pickle(pass)))
  const acc2 = Account.fromPickle(acc.pickle(pass), pass)
  t.true(isObject(acc2))
  t.true(Object.values(acc2.oneTimeKeys).length > 0)
})


test('Account sign', (t) => {
  const acc = new Account()
  acc.generateOneTimeKeys(4)
  t.true(isString(acc.sign('sdasdasdasd')))
})

test('Account sessions', (t) => {
  const alice = new Account();
  const bob = new Account;

  bob.generateOneTimeKeys(4);

  const bobOnetimeKeys =  Object.values(bob.oneTimeKeys)
  const bobFirstOnetimeKey = bobOnetimeKeys[0]

  const session = alice.createOutboundSession(bob.curve25519Key, bobFirstOnetimeKey, SessionConfig.version2());
  const res = session.encrypt('Hello there')
  let { plaintext: decrypted, session: bob_session } = bob.createInboundSession(alice.curve25519Key, res);
  t.true(decrypted  === 'Hello there')
  const message = bob_session.encrypt('ddddd');
  const decrypted2 = session.decrypt(message);
  t.true(decrypted2 === 'ddddd')

  // one time key removes on first usage
  t.false(isEqual(bobOnetimeKeys, Object.values(bob.oneTimeKeys)))
  t.false(Object.values(bob.oneTimeKeys).includes(bobFirstOnetimeKey))
  ///t.true(isString(res))
   //       bob.curve25519_key(),
   //   *bob.one_time_keys().values().next().unwrap(),
//);
})