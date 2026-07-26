	package epiis.unamba.controller;
	
	import java.util.Date;
	import java.util.Optional;
	
	import org.springframework.beans.factory.annotation.Autowired;
	import org.springframework.http.HttpStatus;
	import org.springframework.http.ResponseEntity;
	import org.springframework.security.crypto.password.PasswordEncoder;
	import org.springframework.web.bind.annotation.PostMapping;
	import org.springframework.web.bind.annotation.RequestBody;
	import org.springframework.web.bind.annotation.RequestHeader;
	import org.springframework.web.bind.annotation.RequestMapping;
	import org.springframework.web.bind.annotation.RestController;
	
	import epiis.unamba.dto.AuthResponse;
	import epiis.unamba.model.Usuario;
	import epiis.unamba.repository.UsuarioRepository;
	import epiis.unamba.service.JwtService;
	
	@RestController
	@RequestMapping("/api/auth")
	public class AuthController {
	
		@Autowired
	    private PasswordEncoder passwordEncoder;
		
		@Autowired
		private UsuarioRepository usuarioRepo;
		
		@Autowired
		private JwtService jwtService;
		
		public static class LoginRequest {
			public String username;
			public String password; 
		}
		
		@PostMapping
		public ResponseEntity<?> iniciarSesion(@RequestBody LoginRequest request){ 
			Optional<Usuario> usuario = usuarioRepo.findByUsername(request.username);
			
			if(
					usuario.isPresent() &&
					passwordEncoder.matches(request.password, usuario.get().getPassword())
			) {
				Usuario usuarioValido = usuario.get();			
				String token = jwtService.generarToken(usuarioValido);
				Date emision = jwtService.generarFechaEmision();
				Date expiracion = jwtService.generarFechaExpiracion();
				
				AuthResponse respuesta = new AuthResponse(
					token,
					usuarioValido.getUsername(),
					usuarioValido.getRol(),
					emision,
					expiracion
				);
				
				return ResponseEntity.ok(respuesta);
			}else {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
						.body("{\"error\" : \"Credenciales inválidas\"}");
			}
		}
		
		@PostMapping("/refresh")
		public ResponseEntity<?> refrescarToken(
			@RequestHeader(value = "Authorization", required = false) String authHeader
			){
			
			if(authHeader == null || !authHeader.startsWith("Bearer ")) {
				return ResponseEntity.status(HttpStatus.BAD_REQUEST)
						.body("{\"error\" : \"Falta token de autorización\"}");
			}
			
			String tokenAntiguo = authHeader.substring(7);
			try {
				AuthResponse response = jwtService.refrescarToken(tokenAntiguo);
				return ResponseEntity.ok(response);
			}catch(Exception e) {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
						.body("{\"error\" : \"Token inválido. No se puede renovar\"}");
			}
		}
		
		
		
		
		
		
		
		
		
		
		
	}
