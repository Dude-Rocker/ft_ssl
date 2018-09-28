/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vgladush <vgladush@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/16 23:43:20 by vgladush          #+#    #+#             */
/*   Updated: 2018/09/22 16:19:42 by vgladush         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_H
# define FT_SSL_H

# include "../libft/includes/libft.h"
// # include <conio.h>

# define LEN 64
# define BLEN 80
# define WS 16
# define ROTR(i, j, s) ((i >> j) | (i << (s - j)))
# define ROTL(i, j, s) ((i << j) | (i >> (s - j)))
# define DELT(a, b, c, d, s) (ROTR(a, b, s) ^ ROTR(a, c, s) ^ (a >> d))
# define SIGM(a, b, c, d, s) (ROTR(a, b, s) ^ ROTR(a, c, s) ^ ROTR(a, d, s))

typedef enum		s_flags
{
	PF,
	QF,
	RF,
	SF,
	CF,
	AF,
	VF,
	BF,
	DF,
	OF,
	HF,
	EF,
	IF,
	OU,
	TF
}					t_flags;

typedef enum		s_words
{
	A,
	B,
	C,
	D,
	E,
	F,
	G,
	H,
	TW
}					t_words;

typedef enum		s_hash
{
	NO_SUCH = -1,
	MD_5,
	SHA_224,
	SHA_256,
	SHA_384,
	SHA_512,
	SHA_512_224,
	SHA_512_256,
	BASE_64,
	DES,
	DES_CBC,
	DES_ECB,
	RAND,
	VERSION,
	TOT_CMD
}					t_hash;

typedef	struct		s_ssl
{
	char			*prog[5];
	size_t			size;
	int				type[3];
	int				flg[TF];
	char			*stream;
	char			*res;
	unsigned char	*end;
	size_t			sze;
}					t_ssl;

typedef	struct		s_32x
{
	uint32_t		words[LEN];
	uint32_t		oth[TW];
	uint32_t		inter[10];
}					t_32x;

typedef	struct		s_64x
{
	uint64_t		words[BLEN];
	uint64_t		oth[TW];
	uint64_t		inter[10];
}					t_64x;

typedef	struct		s_des
{
	uint64_t		words[BLEN];
	char			*bt[2];
}					t_des;

typedef void		(*t_hasing)(t_ssl *ssl);
extern t_hasing		g_func[6];
extern const char	*g_cmd[TOT_CMD];
extern const char	*g_ucmd[RAND];
extern const char	g_errdes[237];

void				ft_md5(t_ssl *ssl);
void				ft_debug(t_ssl *ssl, void *src, uint64_t i, int k);
void				free_all(char **av, char *ln, t_ssl *ssl);
void				ft_sha2(t_ssl *ssl);
void				ft_sha5(t_ssl *ssl);
void				get_data(t_ssl *ssl, char **av, int i);
void				ft_command(t_ssl *ssl, char **av, int i);
void				ft_cipher(t_ssl *ssl, char **av, int i);
void				ft_base64(t_ssl *ssl);
void				ft_des(t_ssl *ssl);
void				ft_des_ecb(t_ssl *ssl);

#endif
