/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vgladush <vgladush@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/16 23:42:31 by vgladush          #+#    #+#             */
/*   Updated: 2018/09/22 16:19:42 by vgladush         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_ssl.h"

const char	*g_cmd[TOT_CMD] = {"md5", "sha224", "sha256", "sha384", "sha512",
	"sha512/224", "sha512/256", "base64", "des", "des-cbc", "des-ecb", "rand", "version"};

const char	*g_ucmd[RAND] = {
	"MD5", "SHA224", "SHA256", "SHA384", "SHA512", "SHA512/224", "SHA512/256"};

static const char g_usgmsg[185] = "\' is an invalid command.\n\nStandard \
commands:\nrand\nversion\n\nMessage Digest commands:\nmd5\nsha224\nsha256\n\
sha384\nsha512\nsha512/224\nsha512/256\n\nCipher commands:\nbase64\ndes\n\
des-ecb\ndes-cbc\n\n";

static int	def_flags3(t_ssl *ssl, char **av, int *i)
{
	if (!ft_strcmp(av[*i], "-e") && !(ssl->flg[DF] = 0))
		ssl->flg[EF] = 1;
	else if (!ft_strcmp(av[*i], "-d") && !(ssl->flg[EF] = 0))
		ssl->flg[DF] = 1;
	else if (!ft_strcmp(av[*i], "-a"))
		ssl->flg[AF] = 1;
	else if ((!ft_strcmp(av[*i], "-i") || !ft_strcmp(av[*i], "-v")
		|| !ft_strcmp(av[*i], "-k") || !ft_strcmp(av[*i], "-s") ||
		!ft_strcmp(av[*i], "-p")) && av[(*i += 1)])
	{
		if (!ft_strcmp(av[*i - 1], "-k") && (ssl->flg[HF] = 1))
			ssl->prog[1] = av[*i];
		else if (!ft_strcmp(av[*i - 1], "-v") && (ssl->flg[VF] = 1))
			ssl->prog[2] = av[*i];
		else if (!ft_strcmp(av[*i - 1], "-p") && (ssl->flg[PF] = 1))
			ssl->prog[3] = av[*i];
		else if (!ft_strcmp(av[*i - 1], "-s") && (ssl->flg[SF] = 1))
			ssl->prog[4] = av[*i];
		else if ((ssl->flg[IF] = 1))
			ssl->res = av[*i];
	}
	else
		return (1);
	return (0);
}

static int	def_flags2(t_ssl *ssl, char **av, int *i)
{
	if (ssl->type[0] >= RAND)
		return (1);
	if (ssl->type[0] >= BASE_64)
		return (def_flags3(ssl, av, i));
	if (!ft_strcmp(av[*i], "-p"))
		ssl->flg[PF] = 1;
	else if (!ft_strcmp(av[*i], "-q"))
		ssl->flg[QF] = 1;
	else if (!ft_strcmp(av[*i], "-r"))
		ssl->flg[RF] = 1;
	else if (!ft_strcmp(av[*i], "-s") && av[*i + 1])
	{
		*i += 1;
		ssl->flg[SF] = 1;
		ssl->prog[1] = av[*i];
	}
	else if (!ft_strcmp(av[*i], "-sbs"))
		ssl->flg[DF] = 1;
	else if (!ft_strcmp(av[*i], "-c"))
		ssl->flg[CF] = 1;
	else
		return (1);
	return (0);
}
	

static int	define_flags(t_ssl *ssl, char **av, int *i)
{
	if (!ft_strcmp(av[*i], "-o") && ssl->type[0] != VERSION)
	{
		*i += 1;
		if ((ssl->type[0] == RAND && !ssl->flg[OF]) || !av[*i])
			return (1);
		ssl->flg[OF] = 0;
		ssl->stream = av[*i];
	}
	else if (ssl->type[0] == VERSION && !ft_strcmp(av[*i], "-a"))
		ssl->flg[AF] = 1;
	else if (ssl->type[0] == VERSION && !ft_strcmp(av[*i], "-v"))
		ssl->flg[VF] = 1;
	else if (ssl->type[0] == VERSION && !ft_strcmp(av[*i], "-b"))
		ssl->flg[BF] = 1;
	else if (ssl->type[0] == VERSION && !ft_strcmp(av[*i], "-d"))
		ssl->flg[DF] = 1;
	else if ((ssl->type[0] < BASE_64 || ssl->type[0] == RAND) &&
		!ft_strcmp(av[*i], "-h"))
		ssl->flg[HF] = 1;
	else
		return (def_flags2(ssl, av, i));
	return (0);
}

static int	define_arg(char **av, t_ssl *ssl, int i, int j)
{
	if (!av[0])
		return (ssl->flg[OU]);
	if (!ft_strcmp(av[i], "exit"))
		return (0);
	while (++j < OU)
		ssl->flg[j] = 0;
	ssl->flg[OF] = 1;
	j = 0;
	while (j < TOT_CMD && ft_strcmp(av[i], g_cmd[j]))
		++j;
	ssl->type[0] = (j < TOT_CMD ? j : NO_SUCH);
	if (ssl->type[0] == NO_SUCH)
		ft_dprintf(2, "ft_ssl: Error: \'%s%s", av[i], g_usgmsg);
	else
	{
		i++;
		free_all(0, 0, ssl);
		while (av[i] && !define_flags(ssl, av, &i))
			i++;
		get_data(ssl, av, i);
	}
	return (ssl->flg[OU]);
}

int			main(int ac, char **av)
{
	t_ssl	ssl;
	char	*ln;

	ssl.prog[0] = av[0];
	ssl.flg[OU] = 0;
	srand(time(0));
	if (ac < 2)
	{
		write(2, "usage: ft_ssl command [command opts] [command args]\n", 52);
		write(2, "ft_ssl> ", 8);
		ssl.flg[OU] = (get_next_line(0, &ln) < 1 ? 0 : 1);
		av = ft_strsplit(ln, ' ');
	}
	while (define_arg(av, &ssl, (ac < 2 ? 0 : 1), -1))
	{
		free_all(av, ln, 0);
		write(2, "ft_ssl> ", 8);
		ssl.flg[OU] = (get_next_line(0, &ln) < 1 ? 0 : 1);
		av = ft_strsplit(ln, ' ');
	}
	if (ac < 2)
		free_all(av, ln, 0);
	return (0);
}
