import { StyleSheet } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

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
