class MainPage(Handler):
	def get(self):
		self.response.headers['Content-Type'] = "text/plain"
		visits = 0
		visit_cookie_str = self.request.cookies.get('visits')
		if visit_cookie_val:
			cookie_val = check_secure_val(visit_cookie_str)
			if cookie_val:
				visits = int(cookie_val)

		if visits.isdigit():
			visits = int(visits) + 1
		else:
			visits = 0

		self.response.header.add_header('Set-Cookie', 'visits=%s' % visits)

		if visits > 10000:
			self.write("Your are best ever!")
		else:
			self.write("You've been here %s times!" % visits)
