import 'package:flutter/material.dart';

void main() {
  runApp(const EnclaveApp());
}

class EnclaveApp extends StatelessWidget {
  const EnclaveApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Enclave',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: const SplashScreen(),
    );
  }
}

class SplashScreen extends StatelessWidget {
  const SplashScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Text(
          'enclave',
          style: Theme.of(context).textTheme.headlineMedium,
        ),
      ),
    );
  }
}