#include <gtk/gtk.h>
#include <glib/gunicode.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dh.h"
#include "keys.h"

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

#define KEY_LEN 64
#define ENC_KEY_LEN 32
#define NONCE_LEN 12
#define TAG_LEN 16
#define MAX_MSG_LEN (64 * 1024)

static GtkTextBuffer* tbuf;
static GtkTextBuffer* mbuf;
static GtkTextView* tview;
static GtkTextMark* mark;

static pthread_t trecv;
static int sockfd = -1;
static int listensock = -1;
static int isclient = 1;

static unsigned char session_key[KEY_LEN];
static unsigned char enc_key[ENC_KEY_LEN];

typedef struct {
	char* text;
	const char* tag;
} UiLine;

static void* recvMsg(void* arg);
static gboolean shownewmessage(gpointer msg);
static gboolean showstatus(gpointer msg);

static void die(const char* msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

static int send_all(int fd, const void* buf, size_t len)
{
	const unsigned char* p = (const unsigned char*)buf;
	while (len > 0) {
		ssize_t n = send(fd, p, len, 0);
		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		p += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

static int recv_exact(int fd, void* buf, size_t len)
{
	unsigned char* p = (unsigned char*)buf;
	while (len > 0) {
		ssize_t n = recv(fd, p, len, 0);
		if (n == 0) return 0;
		if (n < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		p += (size_t)n;
		len -= (size_t)n;
	}
	return 1;
}

static int send_mpz_socket(int fd, mpz_t x)
{
	size_t nB = 0;
	unsigned char* buf = (unsigned char*)mpz_export(NULL, &nB, -1, 1, 0, 0, x);
	if (!buf) {
		nB = 1;
		buf = (unsigned char*)malloc(1);
		if (!buf) return -1;
		buf[0] = 0;
	}
	if (nB > UINT32_MAX) {
		free(buf);
		return -1;
	}
	uint32_t n = htonl((uint32_t)nB);
	if (send_all(fd, &n, sizeof(n)) < 0 || send_all(fd, buf, nB) < 0) {
		free(buf);
		return -1;
	}
	free(buf);
	return 0;
}

static int recv_mpz_socket(int fd, mpz_t x)
{
	uint32_t n_be = 0;
	int rc = recv_exact(fd, &n_be, sizeof(n_be));
	if (rc <= 0) return rc;
	uint32_t n = ntohl(n_be);
	if (n == 0 || n > MAX_MSG_LEN) return -1;
	unsigned char* buf = (unsigned char*)malloc(n);
	if (!buf) return -1;
	rc = recv_exact(fd, buf, n);
	if (rc <= 0) {
		free(buf);
		return rc;
	}
	mpz_import(x, n, -1, 1, 0, 0, buf);
	free(buf);
	return 1;
}

static int do_handshake(int fd, int client)
{
	mpz_t sk, pk, peer_pk;
	mpz_init(sk);
	mpz_init(pk);
	mpz_init(peer_pk);

	if (dhGen(sk, pk) != 0) {
		mpz_clears(sk, pk, peer_pk, NULL);
		return -1;
	}

	int ok = 0;
	if (client) {
		if (send_mpz_socket(fd, pk) == 0 && recv_mpz_socket(fd, peer_pk) > 0) ok = 1;
	} else {
		if (recv_mpz_socket(fd, peer_pk) > 0 && send_mpz_socket(fd, pk) == 0) ok = 1;
	}

	if (!ok) {
		mpz_clears(sk, pk, peer_pk, NULL);
		return -1;
	}

	if (dhFinal(sk, pk, peer_pk, session_key, KEY_LEN) != 0) {
		mpz_clears(sk, pk, peer_pk, NULL);
		return -1;
	}

	memcpy(enc_key, session_key, ENC_KEY_LEN);
	mpz_clears(sk, pk, peer_pk, NULL);
	return 0;
}

static int initServerNet(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	if (listensock < 0) die("socket");
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons((uint16_t)port);

	if (bind(listensock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) die("bind");
	fprintf(stderr, "Listening on port %d...\n", port);
	listen(listensock, 1);

	struct sockaddr_in cli_addr;
	socklen_t clilen = (socklen_t)sizeof(cli_addr);
	sockfd = accept(listensock, (struct sockaddr*)&cli_addr, &clilen);
	if (sockfd < 0) die("accept");
	close(listensock);
	listensock = -1;

	if (do_handshake(sockfd, 0) != 0) return -1;
	return 0;
}

static int initClientNet(const char* hostname, int port)
{
	struct sockaddr_in serv_addr;
	struct hostent* server;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) die("socket");

	server = gethostbyname(hostname);
	if (!server) return -1;

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, (size_t)server->h_length);
	serv_addr.sin_port = htons((uint16_t)port);

	if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) return -1;
	if (do_handshake(sockfd, 1) != 0) return -1;
	return 0;
}

static int encrypt_message(const unsigned char* plaintext, int plaintext_len,
				   unsigned char* nonce, unsigned char* ciphertext, unsigned char* tag)
{
	int len = 0;
	int ciphertext_len = 0;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;

	if (RAND_bytes(nonce, NONCE_LEN) != 1) goto fail;
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) goto fail;
	if (EVP_EncryptInit_ex(ctx, NULL, NULL, enc_key, nonce) != 1) goto fail;
	if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) goto fail;
	ciphertext_len = len;
	if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) goto fail;
	ciphertext_len += len;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) goto fail;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;

fail:
	EVP_CIPHER_CTX_free(ctx);
	return -1;
}

static int decrypt_message(const unsigned char* nonce, const unsigned char* ciphertext,
				   int ciphertext_len, const unsigned char* tag, unsigned char* plaintext)
{
	int len = 0;
	int plaintext_len = 0;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) goto fail;
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, enc_key, nonce) != 1) goto fail;
	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) goto fail;
	plaintext_len = len;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) != 1) goto fail;
	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) goto fail;
	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;

fail:
	EVP_CIPHER_CTX_free(ctx);
	return -1;
}

static int send_encrypted(int fd, const unsigned char* msg, size_t len)
{
	if (len == 0 || len > MAX_MSG_LEN) return -1;

	unsigned char nonce[NONCE_LEN];
	unsigned char tag[TAG_LEN];
	unsigned char* ciphertext = (unsigned char*)malloc(len);
	if (!ciphertext) return -1;

	int clen = encrypt_message(msg, (int)len, nonce, ciphertext, tag);
	if (clen < 0) {
		free(ciphertext);
		return -1;
	}

	uint32_t nlen = htonl((uint32_t)NONCE_LEN);
	uint32_t clen_net = htonl((uint32_t)clen);
	uint32_t tlen = htonl((uint32_t)TAG_LEN);

	int ok =
		send_all(fd, &nlen, sizeof(nlen)) == 0 &&
		send_all(fd, &clen_net, sizeof(clen_net)) == 0 &&
		send_all(fd, &tlen, sizeof(tlen)) == 0 &&
		send_all(fd, nonce, NONCE_LEN) == 0 &&
		send_all(fd, ciphertext, (size_t)clen) == 0 &&
		send_all(fd, tag, TAG_LEN) == 0;

	free(ciphertext);
	return ok ? 0 : -1;
}

static int recv_encrypted(int fd, unsigned char** out, size_t* outlen)
{
	uint32_t nlen_be = 0, clen_be = 0, tlen_be = 0;
	int rc = recv_exact(fd, &nlen_be, sizeof(nlen_be));
	if (rc <= 0) return rc;
	if (recv_exact(fd, &clen_be, sizeof(clen_be)) <= 0) return -1;
	if (recv_exact(fd, &tlen_be, sizeof(tlen_be)) <= 0) return -1;

	uint32_t nlen = ntohl(nlen_be);
	uint32_t clen = ntohl(clen_be);
	uint32_t tlen = ntohl(tlen_be);

	if (nlen != NONCE_LEN || tlen != TAG_LEN || clen == 0 || clen > MAX_MSG_LEN) return -1;

	unsigned char nonce[NONCE_LEN];
	unsigned char tag[TAG_LEN];
	unsigned char* ciphertext = (unsigned char*)malloc(clen);
	unsigned char* plaintext = (unsigned char*)malloc((size_t)clen + 1);
	if (!ciphertext || !plaintext) {
		free(ciphertext);
		free(plaintext);
		return -1;
	}

	if (recv_exact(fd, nonce, NONCE_LEN) <= 0 ||
		recv_exact(fd, ciphertext, clen) <= 0 ||
		recv_exact(fd, tag, TAG_LEN) <= 0) {
		free(ciphertext);
		free(plaintext);
		return -1;
	}

	int plen = decrypt_message(nonce, ciphertext, (int)clen, tag, plaintext);
	free(ciphertext);
	if (plen < 0) {
		free(plaintext);
		return -1;
	}
	plaintext[plen] = 0;
	*out = plaintext;
	*outlen = (size_t)plen;
	return 1;
}

static int shutdownNetwork(void)
{
	if (sockfd >= 0) {
		shutdown(sockfd, SHUT_RDWR);
		close(sockfd);
		sockfd = -1;
	}
	if (listensock >= 0) {
		close(listensock);
		listensock = -1;
	}
	return 0;
}

static const char* usage =
	"Usage: %s [OPTIONS]...\n"
	"Secure chat (CCNY computer security project).\n\n"
	"   -c, --connect HOST  Attempt a connection to HOST.\n"
	"   -l, --listen        Listen for new connections.\n"
	"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
	"   -h, --help          show this message and exit.\n";

static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf, &t0);
	size_t len = strlen(message);
	if (ensurenewline && (len == 0 || message[len - 1] != '\n')) {
		message[len++] = '\n';
		message[len] = '\0';
	}
	gtk_text_buffer_insert(tbuf, &t0, message, (gint)len);

	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf, &t1);
	t0 = t1;
	gtk_text_iter_backward_chars(&t0, (gint)len);

	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf, *tag, &t0, &t1);
			tag++;
		}
	}

	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf, mark, &t1);
	gtk_text_view_scroll_to_mark(tview, mark, 0.0, 0, 0.0, 0.0);
	gtk_text_buffer_delete_mark(tbuf, mark);
}

static gboolean showstatus(gpointer msg)
{
	UiLine* line = (UiLine*)msg;
	char* tags[2] = {(char*)line->tag, NULL};
	tsappend(line->text, tags, 1);
	free(line->text);
	free(line);
	return FALSE;
}

static gboolean shownewmessage(gpointer msg)
{
	char* tags[2] = {"friend", NULL};
	char* friendname = "friend: ";
	tsappend(friendname, tags, 0);
	char* message = (char*)msg;
	tsappend(message, NULL, 1);
	free(message);
	return FALSE;
}

static void post_status_line(const char* text)
{
	UiLine* line = (UiLine*)malloc(sizeof(UiLine));
	if (!line) return;
	line->text = strdup(text);
	line->tag = "status";
	if (!line->text) {
		free(line);
		return;
	}
	g_main_context_invoke(NULL, showstatus, line);
}

static void sendMessage(GtkWidget* w, gpointer data)
{
	(void)data;
	char* tags[2] = {"self", NULL};

	GtkTextIter mstart, mend;
	gtk_text_buffer_get_start_iter(mbuf, &mstart);
	gtk_text_buffer_get_end_iter(mbuf, &mend);
	char* message = gtk_text_buffer_get_text(mbuf, &mstart, &mend, TRUE);
	if (!message) return;

	size_t len = strlen(message);
	if (len == 0) {
		free(message);
		gtk_widget_grab_focus(w);
		return;
	}

	if (send_encrypted(sockfd, (unsigned char*)message, len) != 0) {
		post_status_line("Failed to send encrypted message.");
		free(message);
		return;
	}

	tsappend("me: ", tags, 0);
	tsappend(message, NULL, 1);
	free(message);

	gtk_text_buffer_get_start_iter(mbuf, &mstart);
	gtk_text_buffer_get_end_iter(mbuf, &mend);
	gtk_text_buffer_delete(mbuf, &mstart, &mend);
	gtk_widget_grab_focus(w);
}

static void* recvMsg(void* arg)
{
	(void)arg;
	while (1) {
		unsigned char* plaintext = NULL;
		size_t plen = 0;
		int rc = recv_encrypted(sockfd, &plaintext, &plen);
		if (rc == 0) {
			post_status_line("Peer disconnected.");
			break;
		}
		if (rc < 0) {
			post_status_line("Receive/decrypt failed.");
			break;
		}
		(void)plen;
		g_main_context_invoke(NULL, shownewmessage, plaintext);
	}
	return NULL;
}

int main(int argc, char* argv[])
{
	if (init("params") != 0) {
		fprintf(stderr, "ERROR: failed to read DH params from file\n");
		return 1;
	}

	static struct option long_opts[] = {
		{"connect", required_argument, 0, 'c'},
		{"listen", no_argument, 0, 'l'},
		{"port", required_argument, 0, 'p'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0},
	};

	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX + 1] = "localhost";
	hostname[HOST_NAME_MAX] = '\0';

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg, HOST_NAME_MAX) > 0) strncpy(hostname, optarg, HOST_NAME_MAX);
				hostname[HOST_NAME_MAX] = '\0';
				break;
			case 'l':
				isclient = 0;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage, argv[0]);
				return 0;
			case '?':
			default:
				printf(usage, argv[0]);
				return 1;
		}
	}

	if (isclient) {
		if (initClientNet(hostname, port) != 0) {
			fprintf(stderr, "Connection/handshake failed\n");
			return 1;
		}
	} else {
		if (initServerNet(port) != 0) {
			fprintf(stderr, "Accept/handshake failed\n");
			return 1;
		}
	}

	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* gerr = NULL;

	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder, "layout.ui", &gerr) == 0) {
		g_printerr("Error reading layout.ui: %s\n", gerr->message);
		g_clear_error(&gerr);
		return 1;
	}

	mark = gtk_text_mark_new(NULL, TRUE);
	window = gtk_builder_get_object(builder, "window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));

	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));

	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css, "colors.css", NULL);
	gtk_style_context_add_provider_for_screen(
		gdk_screen_get_default(), GTK_STYLE_PROVIDER(css), GTK_STYLE_PROVIDER_PRIORITY_USER);

	gtk_text_buffer_create_tag(tbuf, "status", "foreground", "#657b83", "style", PANGO_STYLE_ITALIC,
				   NULL);
	gtk_text_buffer_create_tag(tbuf, "friend", "foreground", "#6c71c4", "weight", PANGO_WEIGHT_BOLD,
				   NULL);
	gtk_text_buffer_create_tag(tbuf, "self", "foreground", "#268bd2", "weight", PANGO_WEIGHT_BOLD,
				   NULL);

	gtk_widget_show_all(GTK_WIDGET(window));

	post_status_line("Connected securely.");
	post_status_line("Encrypted session active.");

	if (pthread_create(&trecv, NULL, recvMsg, NULL) != 0) {
		fprintf(stderr, "Failed to create receiver thread.\n");
		return 1;
	}

	gtk_main();

	shutdownNetwork();
	pthread_join(trecv, NULL);
	memset(session_key, 0, sizeof(session_key));
	memset(enc_key, 0, sizeof(enc_key));
	return 0;
}
