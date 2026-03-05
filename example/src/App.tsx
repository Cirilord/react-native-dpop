import { Text, StyleSheet, TouchableHighlight } from 'react-native';
import { DPoP } from 'react-native-dpop';
import { SafeAreaView } from 'react-native-safe-area-context';

export default function App() {
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
    <SafeAreaView style={styles.container}>
      <TouchableHighlight onPress={onPress}>
        <Text>Teste</Text>
      </TouchableHighlight>
    </SafeAreaView>
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
