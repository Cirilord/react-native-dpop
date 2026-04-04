import { useCallback } from 'react';
import { StyleSheet, Text, TouchableHighlight, View } from 'react-native';
import { DPoP } from 'react-native-dpop';

export default function DPoPExampleContent(): JSX.Element {
  const onPress = useCallback(async () => {
    const dPoP = await DPoP.generateProof({
      htm: 'GET',
      htu: 'https://api.example.com/resource',
      kid: '123',
      requireHardwareBacked: false,
    });

    const publicKeyThumbprint = await dPoP.getPublicKeyThumbprint();

    console.log(dPoP, dPoP.proof, publicKeyThumbprint);
    console.log(await dPoP.getPublicKey('DER'));
    console.log(await dPoP.getPublicKey('JWK'));
    console.log(await dPoP.getPublicKey('RAW'));
    console.log(await dPoP.signWithDPoPPrivateKey('RAW'));
    console.log(await dPoP.isBoundToAlias());
    console.log(await DPoP.getKeyInfo());
  }, []);

  return (
    <View style={styles.container}>
      <TouchableHighlight onPress={onPress} style={styles.button}>
        <Text style={styles.buttonText}>Teste</Text>
      </TouchableHighlight>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    alignItems: 'center',
    backgroundColor: 'white',
    flex: 1,
    justifyContent: 'center',
  },
  button: {
    alignItems: 'center',
    backgroundColor: 'blue',
    borderRadius: 4,
    height: 44,
    justifyContent: 'center',
    paddingHorizontal: 16,
    width: '80%',
  },
  buttonText: {
    color: '#ffffff',
  },
});
