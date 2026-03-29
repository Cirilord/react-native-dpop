import { SafeAreaView, StyleSheet } from 'react-native';

import DPoPExampleContent from '../shared/DPoPExampleContent';

export default function App() {
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
