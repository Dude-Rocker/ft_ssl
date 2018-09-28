/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_cipher.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vgladush <vgladush@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/31 13:34:38 by vgladush          #+#    #+#             */
/*   Updated: 2018/09/22 16:19:38 by vgladush         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_ssl.h"

static int	check_hex(char **s, int j, int i)
{
	char	*res;

	while (s[j][i])
	{
		if (s[j][i] > 96 && s[j][i] < 103)
			s[j][i] -= 32;
		else if (!ft_isdigit(s[j][i]) && (s[j][i] > 70 || s[j][i] < 65))
			return (1);
		i++;
	}
	res = ft_strnew(WS);
	i = -1;
	while (++i < WS)
		res[i] = (s[j][i] ? s[j][i] : '0');
	s[j] = res;
	return (0);
}

// static int	crt_psw(t_ssl *ssl, char *ps)
// {
// 	if (ft_strcmp(ssl->prog[3], ps))
// 	{
// 		free(ssl->prog[3]);
// 		ft_dprintf(2, "Verify failure\nbad password read\n");
// 		return (1);
// 	}
// }

static int	check_pass(t_ssl *ssl)
{
	if (!ssl->flg[HF] && !ssl->flg[PF])
	{
		// ssl->prog[3] = ft_strdup(getpass("enter des encryption password:"));
		// if (!crt_psw(ssl, getpass("Verifying - enter des encryption password:")))
			return (0);
	}
	else if (ssl->type[0] != DES_ECB && ssl->flg[HF] && !ssl->flg[VF])
		ft_dprintf(2, "v undefined\n");
	else if (ssl->type[0] != DES_ECB && check_hex(ssl->prog, 2, 0))
		ft_dprintf(2, "non-hex digit\ninvalid hex v value\n");
	else if (check_hex(ssl->prog, 1, 0))
	{
		if (ssl->type[0] != DES_ECB)
			free(ssl->prog[2]);
		ft_dprintf(2, "non-hex digit\ninvalid hex k value\n");
	}
	else
		return (0);
	return (1);
}

static void	print_res(t_ssl *ssl)
{
	close(ssl->sze);
	g_func[ssl->type[1]](ssl);
	if (ssl->res)
		write(ssl->flg[OF], ssl->res, ft_strlen(ssl->res));
	else
		ft_dprintf(2, "ft_ssl: %s: Error: invalid input\n",
			g_cmd[ssl->type[0]]);
	if (ssl->res)
		free(ssl->res);
	free(ssl->stream);
}

void		ft_cipher(t_ssl *ssl, char **av, int i)
{
	if (!av[i] && (!ft_strcmp(av[i - 1], "-k") || !ft_strcmp(av[i - 1], "-v")
		|| !ft_strcmp(av[i - 1], "-p") || !ft_strcmp(av[i - 1], "-s")
		|| !ft_strcmp(av[i - 1], "-o") || !ft_strcmp(av[i - 1], "-i")))
		ft_dprintf(2, g_errdes);
	else if (av[i] && (av[i + 1] || ssl->flg[IF]))
		ft_dprintf(2, "ft_ssl: %s: excess operand \"%s\"\n",
			g_cmd[ssl->type[0]], av[i]);
	else if (ssl->type[0] != BASE_64 && check_pass(ssl))
		return ;
	else
	{
		if (av[i])
			ssl->sze = open(av[i], O_RDONLY);
		else
			ssl->sze = (ssl->res ? open(ssl->res, O_RDONLY) : 0);
		ssl->flg[OU] = (!ssl->sze ? 0 : ssl->flg[OU]);
		if (!(ssl->stream = get_stream(ssl->sze, &ssl->size)))
			ft_dprintf(2, "ft_ssl: %s: %s: No such file or directory\n",
				g_cmd[ssl->type[0]], (av[i] ? av[i] : ssl->res));
		else
			print_res(ssl);
	}
}

// When the user does not have a cryptographically secure key, a new one must be created.
// This is why when a key is not provided, OpenSSL asks the user for a password. The key is generated using a Password-Based Key Derivation Function, or PBKDF.
// the salt is purely random data that changes every time. (man 4 random)

// To make your own keys from passwords, you will have to implement your own PBKDF.
// You must read data from STDIN (using getpass or readpassphrase or getch)