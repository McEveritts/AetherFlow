package models

type User struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	Role      string `json:"role"`
	GoogleID  string `json:"-"`
	IsOAuth   bool   `json:"is_oauth"`
}
