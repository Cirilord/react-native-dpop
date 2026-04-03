import { SafeAreaView, StyleSheet } from 'react-native';

import DPoPExampleContent from '../shared/DPoPExampleContent';

export default function App(): JSX.Element {
  return (
    <SafeAreaView style={styles.container}>
      <DPoPExampleContent />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
});
