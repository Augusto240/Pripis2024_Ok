import { Component } from '@angular/core';
import { LoginService } from '../login.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {
  usuario = '';
  senha = '';
  loginInvalid = false;
  errorMessage = '';
  constructor(private login: LoginService, private router: Router) {}

  fazerLogin(): void { // Faz o login
    this.login.login(this.usuario, this.senha).subscribe(
      (response) => {
        if (response.auth == true) {
          this.login.autenticado = true; // Define a variavel autenticado como true
          this.router.navigate(['/lista']); // Navega para a página de lista
        }
      },
      (error) => {
        if (error.status === 0) {
          this.errorMessage = 'Erro de conexão. Verifique sua internet e tente novamente.'; // Erro de conexão
        } else if (error.status >= 500) {
          this.errorMessage = 'Erro no servidor. Tente novamente mais tarde.'; // Erro de servidor
        } else if (error.status === 401) {
          this.errorMessage = 'Login ou senha inválidos. Verifique os campos e tente novamente.'; // Erro de login
        } else {
          this.errorMessage = 'Login ou senha inválidos. Verifique os campos e tente novamente.'; // Outros erros
        }
        this.loginInvalid = true; // Mostra o alerta de erro
      }
    )
  }
}
