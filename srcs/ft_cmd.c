/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_cmd.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vgladush <vgladush@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/16 23:42:31 by vgladush          #+#    #+#             */
/*   Updated: 2018/09/22 16:19:42 by vgladush         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_ssl.h"

static const char g_errmsg[287] = "options are\n-c\t\tto output the digest \
with separating colons\n-r\t\tto output the digest in coreutils format\n-q\t\t\
quiet mode\n-s\t\tprint the sum of the given string\n-p\t\techo STDIN to \
STDOUT\n-h\t\toutput as hex dump\n-o <file>\toutput to file rather than \
stdout\n-sbs\t\tdeveloper mode (step by step)\n";

const char g_errdes[237] = "options are\n-i <file>\tinput file\
\n-o <file>\toutput file\n-p <arg>\tpassword in ascii is the next argument\
\n-e\t\tencrypt\n-d\t\tdecrypt\n-a\t\tbase64 encode/decode, depending on \
encryption flag\n-k/-v/-s\tkey/vector/salt in hex is the next arguement\n";

t_hasing	g_func[6] = {ft_md5, ft_sha2, ft_sha5, ft_base64, ft_des,
	ft_des_ecb};

static void	ft_debug_print(t_ssl *ssl, void *src, uint64_t k, int j)
{
	int		i;

	if (k == 1)
	{
		i = -1;
		ft_dprintf(ssl->flg[OF], "Welcome to developer mode\n%s uses %d %d-bit \
words for encryption. Initially initialized (their copy is saved):\n",
g_ucmd[ssl->type[0]], j, (ssl->type[0] < SHA_384 ? 32 : 64));
		while (ssl->type[0] < SHA_384 && ++i < j)
			ft_dprintf(ssl->flg[OF], "[%d]%#.8x ", i, ((t_32x*)src)->oth[i]);
		while (ssl->type[0] >= SHA_384 && ++i < j)
			ft_dprintf(ssl->flg[OF], "[%d]%#.16zx ", i, ((t_64x*)src)->oth[i]);
		write(ssl->flg[OF], "\n\n", 2);
	}
	i = -1;
	ft_dprintf(ssl->flg[OF], "words after %u cycle:\n", k);
	while (ssl->type[0] < SHA_384 && ++i < j)
		ft_dprintf(ssl->flg[OF], "[%d]%#.8x ", i, ((t_32x*)src)->inter[i]);
	while (ssl->type[0] >= SHA_384 && ++i < j)
		ft_dprintf(ssl->flg[OF], "[%d]%#.16zx ", i, ((t_64x*)src)->inter[i]);
}

void		ft_debug(t_ssl *ssl, void *src, uint64_t i, int k)
{
	int		j;

	if (!ssl->flg[DF])
		return ;
	j = (ssl->type[0] == MD_5 ? 4 : 8);
	ft_debug_print(ssl, src, i, j);
	write(ssl->flg[OF], "\n\n", 2);
	if (!(i % k))
	{
		ft_dprintf(ssl->flg[OF], "after every %u cycles, the words are added \
to the previously saved copy of the words, and again we save a copy of these \
(already merged) words:\n", k);
		i = -1;
		while (ssl->type[0] < SHA_384 && ++i < (uint64_t)j)
			ft_dprintf(ssl->flg[OF], "[%u]%#.8x(%#.8x + %#.8x) ", i,
				((t_32x*)src)->inter[i] + ((t_32x*)src)->oth[i],
				((t_32x*)src)->inter[i], ((t_32x*)src)->oth[i]);
		while (ssl->type[0] >= SHA_384 && ++i < (uint64_t)j)
			ft_dprintf(ssl->flg[OF], "[%u]%#.16zx(%#.16zx + %#.16zx) ", i,
				((t_64x*)src)->inter[i] + ((t_64x*)src)->oth[i],
				((t_64x*)src)->inter[i], ((t_64x*)src)->oth[i]);
		write(ssl->flg[OF], "\n\n", 2);
	}
}

static void	print_res(char *src, t_ssl *ssl)
{
	g_func[ssl->type[1]](ssl);
	if (ssl->flg[PF] && !(ssl->flg[PF] = 0))
		write(ssl->flg[OF], ssl->stream, ft_strlen(ssl->stream));
	if (src && !ssl->flg[QF] && !ssl->flg[RF])
		ft_dprintf(ssl->flg[OF], "%s (%s) = ", g_ucmd[ssl->type[0]], src);
	write(ssl->flg[OF], ssl->res, ft_strlen(ssl->res));
	if (src && !ssl->flg[QF] && ssl->flg[RF])
		ft_dprintf(ssl->flg[OF], " %s", src);
	write(ssl->flg[OF], "\n", 1);
}

static void	find_res(char *src, t_ssl *ssl, int fd)
{
	if (fd == -2)
	{
		ssl->stream = ft_strdup(src);
		src = ft_joinfree("\"", src, 0);
		src = ft_joinfree(src, "\"", 1);
	}
	else if (!(ssl->stream = get_stream(fd, &ssl->size)))
	{
		ft_dprintf(2, "ft_ssl: %s: %s: No such file or directory\n",
			g_cmd[ssl->type[0]], src);
		return ;
	}
	if (fd > 2)
		close(fd);
	print_res(src, ssl);
	if (fd == -2)
		free(src);
	else if (!fd)
		ssl->flg[OU] = 0;
	free(ssl->stream);
	free(ssl->res);
	free(ssl->end);
}

void		get_data(t_ssl *ssl, char **av, int i)
{
	if (!ssl->flg[OF])
		ssl->flg[OF] = open(ssl->stream, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	ssl->flg[OF] = (ssl->flg[OF] > 2 ? ssl->flg[OF] : 1);
	if (ssl->type[0] < RAND && av[i] && av[i][0] == '-')
		ft_dprintf(2, "ft_ssl: %s: unknown option '%s'\n%s", g_cmd[ssl->type[0]],
			av[i], (ssl->type[0] < BASE_64 ? g_errmsg : g_errdes));
	else if (ssl->type[0] < BASE_64)
	{
		if ((ssl->flg[PF] || (!av[i] && !ssl->flg[SF])))
			find_res(0, ssl, 0);
		if (ssl->flg[SF])
			find_res(ssl->prog[1], ssl, -2);
		i--;
		while (av[++i])
			find_res(av[i], ssl, open(av[i], O_RDONLY));
	}
	else if (ssl->type[0] < RAND)
		ft_cipher(ssl, av, i);
	else
		ft_command(ssl, av, i);
	if (ssl->flg[OF] > 2)
		close(ssl->flg[OF]);
}
