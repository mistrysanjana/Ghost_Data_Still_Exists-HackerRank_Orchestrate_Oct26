import 'package:flutter/material.dart';

void main() => runApp(MyApp());

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: Text('Form Example')),
        body: Padding(
          padding: EdgeInsets.all(16),
          child: FormWidget(),
        ),
      ),
    );
  }
}

class FormWidget extends StatefulWidget {
  @override
  State<FormWidget> createState() => FormWidgetState();
}

class FormWidgetState extends State<FormWidget> {
  final _formKey = GlobalKey<FormState>();

  @override
  Widget build(BuildContext context) {
    return Form(
      key: _formKey,
      child: Column(
        children: [
          TextFormField(
            decoration: InputDecoration(labelText: 'Name'),
            validator: (v) =>
                v == null || v.isEmpty ? 'Enter your name' : null,
          ),
          TextFormField(
            decoration: InputDecoration(labelText: 'Email'),
            validator: (v) =>
                v == null || !v.contains('@') ? 'Enter valid email' : null,
          ),
          TextFormField(
            decoration: InputDecoration(labelText: 'Password'),
            obscureText: true,
            validator: (v) =>
                v == null || v.length < 6 ? 'Enter 6 characters' : null,
          ),
          TextFormField(
            decoration: InputDecoration(labelText: 'Phone'),
            keyboardType: TextInputType.phone,
            validator: (v) =>
                v == null || v.length != 10 ? 'Enter valid phone' : null,
          ),
          TextFormField(
            decoration: InputDecoration(labelText: 'Address'),
            validator: (v) =>
                v == null || v.isEmpty ? 'Enter address' : null,
          ),
          ElevatedButton(
            onPressed: () {
              if (_formKey.currentState!.validate()) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text('Form submitted successfully')),
                );
              }
            },
            child: Text('Submit'),
          ),
        ],
      ),
    );
  }
}

