import { StyleSheet, Text, TouchableHighlight, View } from 'react-native';
import { DPoP } from 'react-native-dpop';

export default function DPoPExampleContent() {
  const onPress = async () => {
    const dpop = await DPoP.generateProof({
      htm: 'GET',
      htu: 'https://api.example.com/resource',
      kid: '123',
    });

    const thumbprint = await dpop.calculateThumbprint();

    console.log(dpop, dpop.proof, thumbprint);
    console.log(await dpop.getPublicKey('DER'));
    console.log(await dpop.getPublicKey('JWK'));
    console.log(await dpop.getPublicKey('RAW'));
    console.log(await dpop.signWithDpopPrivateKey('RAW'));
    console.log(await dpop.isBoundToAlias());
    console.log(await DPoP.getKeyInfo());
  };

  return (
    <View style={styles.container}>
      <TouchableHighlight onPress={onPress}>
        <Text>Teste</Text>
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
});
