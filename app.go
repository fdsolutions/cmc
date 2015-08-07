package main

func main() {
	r := gin.Default()

	r.Run(":8080") // listen and serve on 0.0.0.0:8080
}
