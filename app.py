@@ .. @@
 @app.route('/remote_scan', methods=['POST'])
 def remote_scan():
     try:
         data = request.get_json()
         hostname = (data.get('hostname') or '').strip()
         username = (data.get('username') or '').strip()
+        password = (data.get('password') or '').strip()  # Nuevo campo para contraseña
         key_file_raw = data.get('key_file')
         key_file = key_file_raw.strip() if key_file_raw else None
         port = int(data.get('port', 22))
         scan_type = data.get('scan_type', 'standard')
         
         # Validación más robusta de parámetros
         if not hostname or not username:
             return jsonify({'error': 'Hostname y username son requeridos'}), 400
         
+        # Validar que se proporcione clave privada O contraseña
+        if not key_file and not password:
+            return jsonify({'error': 'Debe proporcionar una clave privada o contraseña'}), 400
+        
         if port < 1 or port > 65535:
             return jsonify({'error': 'Puerto debe estar entre 1 y 65535'}), 400