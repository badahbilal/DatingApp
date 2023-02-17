import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class AccountService {
  baseUr = 'https://localhost:5001/api/';

  constructor(private http : HttpClient) { }

  login(model: any) {
    return this.http.post(this.baseUr + 'account/login', model);
  }
}
