package com.olx.dto;


public class RegisterUser {
		private int id;
		private String firstName;
		private String lastName;
		private String userName;
		private String password;
		private String email;
		private String phone;
		private String active;
		private String roles;
		public RegisterUser(String firstName, String lastName, String userName, String password, String email,
				String phone, String active, String roles) {
			super();
			this.firstName = firstName;
			this.lastName = lastName;
			this.userName = userName;
			this.password = password;
			this.email = email;
			this.phone = phone;
			this.active = active;
			this.roles = roles;
		}
		
		public RegisterUser(int id, String firstName, String lastName, String userName, String password, String email,
				String phone, String active, String roles) {
			super();
			this.id = id;
			this.firstName = firstName;
			this.lastName = lastName;
			this.userName = userName;
			this.password = password;
			this.email = email;
			this.phone = phone;
			this.active = active;
			this.roles = roles;
		}


		public RegisterUser() {
			
		}
		
		
		public int getId() {
			return id;
		}
		public void setId(int id) {
			this.id = id;
		}
		public String getFirstName() {
			return firstName;
		}
		public void setFirstName(String firstName) {
			this.firstName = firstName;
		}
		public String getLastName() {
			return lastName;
		}
		public void setLastName(String lastName) {
			this.lastName = lastName;
		}
		public String getUserName() {
			return userName;
		}
		public void setUserName(String userName) {
			this.userName = userName;
		}
		public String getPassword() {
			return password;
		}
		public void setPassword(String password) {
			this.password = password;
		}
		public String getEmail() {
			return email;
		}
		public void setEmail(String email) {
			this.email = email;
		}
		public String getPhone() {
			return phone;
		}
		public void setPhone(String phone) {
			this.phone = phone;
		}
		
		public String getActive() {
			return active;
		}

		public void setActive(String active) {
			this.active = active;
		}

		public String getRoles() {
			return roles;
		}

		public void setRoles(String roles) {
			this.roles = roles;
		}

		@Override
		public String toString() {
			return "RegisterUser [id=" + id + ", firstName=" + firstName + ", lastName=" + lastName + ", userName="
					+ userName + ", password=" + password + ", email=" + email + ", phone=" + phone
					+ "]";
		}
		
		
		
		
		

}
